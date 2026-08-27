"""Slow-loop reward: a pure function of the epoch's :class:`Observation` (PREREG section 7).

Implements the section 7.2 template exactly::

    r_t = sum_p [ log s2_p(t-1) - log s2_p(t) + beta * min(1, C_p(t) / kappa) ]
          - sum_r lambda_r(t) * max(0, c_r(t) - B_r)

where ``s2_p`` is the posterior variance of the per-path loss estimate from the samples
*received* for path ``p`` (Beta-Binomial), ``C_p`` the path's CUSUM statistic against its own
running baseline, ``c_r`` the *measured* consumption of resource ``r``, ``B_r`` its cap and
``lambda_r`` the current shadow price.  Nothing here may read the injected fault set, the
fault stream, an oracle or any per-element ground truth; the module imports nothing from
``sim`` and :func:`compute_reward` takes no ground-truth argument at all.

Constants ``beta`` and ``kappa`` live in ``conf/mcp/reward.yaml``.
"""
import logging
import math
import os
from typing import Dict, Iterable, Optional

from controller.infer import InferState, load_frozen_config
from controller.types import Observation

__all__ = ["RewardConstants", "load_constants", "compute_reward", "make_observation"]

logger = logging.getLogger(__name__)

_HERE = os.path.dirname(os.path.abspath(__file__))
REWARD_CONFIG_PATH = os.path.join(os.path.dirname(_HERE), "conf", "mcp", "reward.yaml")


class RewardConstants:
    """The frozen constants of section 7.2 (``beta``, ``kappa``) plus a numeric floor."""

    __slots__ = ("beta", "kappa", "sigma2_floor")

    def __init__(self, beta: float, kappa: float, sigma2_floor: float = 1e-12) -> None:
        self.beta = beta
        self.kappa = kappa
        self.sigma2_floor = sigma2_floor


def load_constants(path: str = REWARD_CONFIG_PATH) -> RewardConstants:
    """Read ``conf/mcp/reward.yaml`` (flat ``key: value`` lines)."""
    cfg = load_frozen_config(path)
    return RewardConstants(beta=float(cfg["beta"]), kappa=float(cfg["kappa"]),
                           sigma2_floor=float(cfg.get("sigma2_floor", 1e-12)))


def compute_reward(obs: Observation, prices: Dict[str, float],
                   constants: Optional[RewardConstants] = None) -> float:
    """Section 7.2 reward for one epoch.

    Args:
        obs: The epoch's observation record (posterior variances, path CUSUMs, measured
            resource usage and caps).
        prices: Shadow price ``lambda_r(t)`` per resource id.
        constants: ``beta``/``kappa``; loaded from ``conf/mcp/reward.yaml`` if omitted.

    Returns:
        ``r_t`` as a float.  Paths present in ``obs.sigma2`` but absent from ``sigma2_prev``
        contribute no uncertainty-reduction term; resources without a price are free.
    """
    c = constants if constants is not None else load_constants()
    floor = c.sigma2_floor
    r = 0.0
    for p, s2 in obs.sigma2.items():
        s2_prev = obs.sigma2_prev.get(p)
        if s2_prev is not None:
            r += math.log(max(s2_prev, floor)) - math.log(max(s2, floor))
        r += c.beta * min(1.0, obs.cusum.get(p, 0.0) / c.kappa)
    for res, usage in obs.usage.items():
        cap = obs.caps.get(res)
        if cap is not None:
            r -= prices.get(res, 0.0) * max(0.0, usage - cap)
    logger.debug("reward epoch=%d r=%.6f", obs.epoch, r)
    return r


def make_observation(prev: InferState, cur: InferState, paths: Iterable[str],
                     usage: Dict[str, float], caps: Dict[str, float]) -> Observation:
    """Build the :class:`Observation` record from two consecutive localizer states.

    Only received-sample posteriors and measured resource counters enter the record.
    """
    paths = list(paths)
    return Observation(
        epoch=cur.epoch,
        sigma2_prev={p: prev.get(p).loss_var for p in paths},
        sigma2={p: cur.get(p).loss_var for p in paths},
        cusum={p: cur.get(p).cusum for p in paths},
        usage=dict(usage),
        caps=dict(caps),
    )
