"""The ONE frozen localizer shared by every arm (PREREG section 3.3).

Every arm converts its raw measurements (probes, tags, mirrored copies, sketch deltas, NIC
counter deltas) into :class:`Sample` records with its own *sample adapter*; everything after
that point lives here and is identical for MCP, A1-A7 and B1-B13.  The module is frozen by
recording ``sha256(source of this file)`` in ``conf/infer/frozen.yaml`` (see ``freeze.py``)
and :func:`module_hash` lets a run verify it at start-up.

Pipeline per epoch (:func:`update`):

1. **De-aggregation.** A path-level sample is attributed to each of the ``n`` links of the
   path with a *uniform prior*: every link receives ``delivered / n`` and ``lost / n`` as
   fractional pseudo-counts and each latency sample divided by ``n``.  No rounding is applied
   (Beta/Normal-Gamma posteriors accept real-valued pseudo-counts); this keeps the update
   exactly linear so that Pingmesh-style intersection is a special case.  The path itself is
   also kept as a composite element.  A sample (or de-aggregated share) with
   ``delivered + lost == 0`` and no latency samples carries no information: it is dropped
   before any state is touched (an idle-but-probed link is treated as not probed).
2. **Posteriors.** Per element: Beta(alpha, beta) on the loss rate (alpha counts losses) and
   Normal-Gamma(mu, kappa, a, b) on latency.  Before each observed epoch the pseudo-counts
   are discounted toward the prior by the frozen factor ``forget_rho`` (an exponential
   forgetting window of ``1/(1-rho)`` epochs), so the posterior tracks the *recent* state and
   the CUSUM below sees a change rather than a 1/n-diluted average.
3. **Change detection.** Loss: an upper-sided Page/binomial log-likelihood-ratio CUSUM per
   element on this epoch's counts (``n`` trials, ``x`` losses) against the baseline rate
   ``p0`` — the *prior-free* loss rate ``(alpha-alpha0)/((alpha-alpha0)+(beta-beta0))`` of
   the forgotten pseudo-counts (the element's own EWMA of it, or the pool's), floored at
   ``p_floor``; the Beta posterior mean keeps its prior and serves ranking tie-breaks and the
   reward for a shift to ``p1 = p0 + delta_loss``:
   ``S+ <- max(0, S+ + x*log(p1/p0) + (n-x)*log((1-p1)/(1-p0)))`` (nats).  A clean probe of
   any size gives a negative increment, so light clean probes never alarm.  Latency: a
   two-sided CUSUM on the posterior-mean latency against its running baseline (an
   exponential moving average of the posterior mean).  For the element's first ``baseline_warmup_epochs``
   observed epochs the baseline simply follows the posterior mean and no CUSUM increment is
   taken, so that the decay of the prior pseudo-counts is not read as a change.
   ``baseline_mode: pooled`` replaces the per-element baseline with the fabric-wide pooled
   posterior mean over all atomic elements observed so far (pooled pseudo-counts, same
   forgetting, one pool update per epoch); warm-up then counts pool updates, not per-element
   observations, so a sparsely probed outlier is compared against its peers at its first
   observation.  Per-element posteriors are unchanged in both modes.
   Latency increments are normalised by the slack ``k``:
   ``S+ <- max(0, S+ + (x - b)/k - 1)``, ``S- <- max(0, S- + (b - x)/k - 1)``
   (``S-`` of loss is identically 0).
4. **Ranking** (:func:`localize`): elements ordered by CUSUM statistic (max of loss and
   latency, max of the two sides), ties broken by posterior-mean loss then element id; the
   anomaly bit is 1 iff some element with at least ``alarm_min_observations`` observations
   has a statistic above ``h`` (default 1, i.e. the top-ranked statistic exceeds ``h``).

Everything is deterministic: no randomness, no wall-clock reads.
"""
import hashlib
import logging
import math
import os
from dataclasses import dataclass, field, replace
from typing import Dict, Iterable, List, NamedTuple, Optional, Sequence, Tuple

from controller.types import Sample

__all__ = [
    "Sample",
    "ElementState",
    "InferState",
    "Localization",
    "load_frozen_config",
    "update",
    "localize",
    "module_hash",
    "loss_posterior_var",
]

logger = logging.getLogger(__name__)

_HERE = os.path.dirname(os.path.abspath(__file__))
FROZEN_CONFIG_PATH = os.path.join(os.path.dirname(_HERE), "conf", "infer", "frozen.yaml")


# --------------------------------------------------------------------------------------------
# Configuration (flat ``key: value`` file; PyYAML is not available on the switch's python3.8)
# --------------------------------------------------------------------------------------------
def load_frozen_config(path: str = FROZEN_CONFIG_PATH) -> Dict[str, str]:
    """Parse ``conf/infer/frozen.yaml`` as flat ``key: value`` lines (comments ignored)."""
    cfg: Dict[str, str] = {}
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.split("#", 1)[0].strip()
            if ":" in line:
                key, val = line.split(":", 1)
                cfg[key.strip()] = val.strip()
    return cfg


def _cfg_float(cfg: Dict[str, str], key: str, default: float) -> float:
    return float(cfg.get(key, default))


try:
    _FROZEN = load_frozen_config()
except OSError:  # config absent (e.g. first freeze) -> code defaults below
    _FROZEN = {}

DELTA_LOSS = _cfg_float(_FROZEN, "delta_loss", 1e-3)
P_FLOOR = _cfg_float(_FROZEN, "p_floor", 1e-6)
K_CUSUM_LATENCY_US = _cfg_float(_FROZEN, "k_cusum_latency_us", 20.0)
H_DEFAULT = _cfg_float(_FROZEN, "h_default", 6.5)
BASELINE_GAMMA = _cfg_float(_FROZEN, "baseline_gamma", 0.05)
FORGET_RHO = _cfg_float(_FROZEN, "forget_rho", 0.9)
BASELINE_WARMUP = int(_cfg_float(_FROZEN, "baseline_warmup_epochs", 10))
BASELINE_MODE = _FROZEN.get("baseline_mode", "per_element")
BASELINE_MODES = ("per_element", "pooled")
ALARM_MIN_OBS = int(_cfg_float(_FROZEN, "alarm_min_observations", 1))
PRIOR_BETA_ALPHA = _cfg_float(_FROZEN, "prior_beta_alpha", 1.0)
PRIOR_BETA_BETA = _cfg_float(_FROZEN, "prior_beta_beta", 1.0)
PRIOR_NG_MU = _cfg_float(_FROZEN, "prior_ng_mu", 0.0)
PRIOR_NG_KAPPA = _cfg_float(_FROZEN, "prior_ng_kappa", 1e-3)
PRIOR_NG_ALPHA = _cfg_float(_FROZEN, "prior_ng_alpha", 1e-3)
PRIOR_NG_BETA = _cfg_float(_FROZEN, "prior_ng_beta", 1e-3)


# --------------------------------------------------------------------------------------------
# State
# --------------------------------------------------------------------------------------------
@dataclass(frozen=True)
class ElementState:
    """Posterior, baseline and CUSUM state of one element (immutable; updates return copies)."""

    # Beta posterior on loss rate: alpha = losses (+prior), beta = deliveries (+prior)
    loss_alpha: float = PRIOR_BETA_ALPHA
    loss_beta: float = PRIOR_BETA_BETA
    # Normal-Gamma posterior on latency (microseconds)
    ng_mu: float = PRIOR_NG_MU
    ng_kappa: float = PRIOR_NG_KAPPA
    ng_alpha: float = PRIOR_NG_ALPHA
    ng_beta: float = PRIOR_NG_BETA
    # Running baselines: prior-free loss rate / posterior-mean latency (None until observed)
    base_loss: Optional[float] = None
    base_lat: Optional[float] = None
    n_obs_loss: int = 0
    n_obs_lat: int = 0
    # CUSUM statistics (loss is upper-sided only: cusum_loss_neg stays 0.0)
    cusum_loss_pos: float = 0.0
    cusum_loss_neg: float = 0.0
    cusum_lat_pos: float = 0.0
    cusum_lat_neg: float = 0.0
    last_t_us: int = 0

    @property
    def loss_mean(self) -> float:
        """Posterior mean of the loss rate."""
        return self.loss_alpha / (self.loss_alpha + self.loss_beta)

    @property
    def loss_var(self) -> float:
        """Posterior variance of the loss rate."""
        s = self.loss_alpha + self.loss_beta
        return self.loss_alpha * self.loss_beta / (s * s * (s + 1.0))

    @property
    def loss_rate(self) -> float:
        """Prior-free loss rate from the (forgotten) pseudo-counts; 0.0 if none."""
        lost = self.loss_alpha - PRIOR_BETA_ALPHA
        n = lost + (self.loss_beta - PRIOR_BETA_BETA)
        return lost / n if n > 0.0 else 0.0

    @property
    def latency_mean(self) -> float:
        """Posterior mean of the latency mean (microseconds)."""
        return self.ng_mu

    @property
    def latency_var(self) -> float:
        """Posterior variance of the latency mean: b / (kappa * a) (undefined -> inf)."""
        if self.ng_alpha <= 0.0 or self.ng_kappa <= 0.0:
            return math.inf
        return self.ng_beta / (self.ng_kappa * self.ng_alpha)

    @property
    def cusum(self) -> float:
        """Combined statistic: max over {loss, latency} x {upper, lower} sides."""
        return max(self.cusum_loss_pos, self.cusum_loss_neg, self.cusum_lat_pos, self.cusum_lat_neg)


@dataclass(frozen=True)
class InferState:
    """Whole-fabric localizer state: a mapping element id -> :class:`ElementState`."""

    elements: Dict[str, ElementState] = field(default_factory=dict)
    epoch: int = 0
    pool: ElementState = ElementState()  # fabric-wide pooled posterior (used in pooled mode)

    def get(self, element: str) -> ElementState:
        """State of ``element`` (prior state if never observed)."""
        return self.elements.get(element, ElementState())


class Localization(NamedTuple):
    """Output of :func:`localize`."""

    anomaly: bool
    ranked: List[Tuple[str, float]]
    suspects: List[str]


# --------------------------------------------------------------------------------------------
# Update
# --------------------------------------------------------------------------------------------
def _accumulate(acc: Dict[str, List[float]], lats: Dict[str, List[float]], t_max: Dict[str, int],
                element: str, delivered: float, lost: float,
                latency_us: Sequence[float], t_us: int) -> None:
    dl = acc.setdefault(element, [0.0, 0.0])
    dl[0] += delivered
    dl[1] += lost
    lats.setdefault(element, []).extend(latency_us)
    t_max[element] = max(t_max.get(element, 0), t_us)


def _deaggregate(samples: Iterable[Sample], path_to_links: Dict[str, List[str]]
                 ) -> Tuple[Dict[str, List[float]], Dict[str, List[float]], Dict[str, int]]:
    """Fold samples into per-element (delivered, lost), latency lists and last timestamps."""
    acc: Dict[str, List[float]] = {}
    lats: Dict[str, List[float]] = {}
    t_max: Dict[str, int] = {}
    for s in samples:
        _accumulate(acc, lats, t_max, s.element, float(s.delivered), float(s.lost),
                    s.latency_us, s.t_us)
        links = [l for l in path_to_links.get(s.element, ()) if l != s.element]
        if links:  # never re-attribute a sample to its own element (identity map guard)
            n = float(len(links))
            link_lats = [x / n for x in s.latency_us]
            for link in links:
                _accumulate(acc, lats, t_max, link, s.delivered / n, s.lost / n, link_lats, s.t_us)
    return acc, lats, t_max


def _loss_llr_step(pos: float, n: float, x: float, base: Optional[float], n_obs: int,
                   rate: float, gamma: float, pooled: bool) -> Tuple[float, float]:
    """Upper-sided binomial LLR CUSUM step on counts; returns (S+, new baseline).

    ``base`` and ``rate`` are prior-free loss rates (see ``ElementState.loss_rate``).
    """
    if base is None or n_obs < BASELINE_WARMUP:
        return 0.0, (base if pooled and base is not None else rate)
    p0 = min(max(base, P_FLOOR), 1.0 - 2.0 * DELTA_LOSS)
    p1 = p0 + DELTA_LOSS
    inc = x * math.log(p1 / p0) + (n - x) * math.log((1.0 - p1) / (1.0 - p0))
    new_base = base if pooled else (1.0 - gamma) * base + gamma * rate
    return max(0.0, pos + inc), new_base


def _track(pos: float, neg: float, x: float, base: Optional[float], n_obs: int, k: float,
           gamma: float, pooled: bool = False) -> Tuple[float, float, float]:
    """One two-sided latency CUSUM + baseline step; returns (S+, S-, new baseline).

    During the first ``BASELINE_WARMUP`` observations the baseline follows ``x`` and the
    CUSUM stays at zero.  In pooled mode ``base``/``n_obs`` are the pool's and the returned
    baseline is the pool mean itself (no per-element EMA).
    """
    if base is None or n_obs < BASELINE_WARMUP:
        return 0.0, 0.0, (base if pooled and base is not None else x)
    z = (x - base) / k
    new_base = base if pooled else (1.0 - gamma) * base + gamma * x
    return max(0.0, pos + z - 1.0), max(0.0, neg - z - 1.0), new_base


def _forget(x: float, prior: float, rho: float) -> float:
    return prior + rho * (x - prior)


def _posterior_step(st: ElementState, delivered: float, lost: float, lats: Sequence[float],
                    t_us: int, rho: float) -> ElementState:
    """Forgetting + conjugate posterior update only (no baseline / CUSUM).

    The loss posterior is touched only when ``delivered + lost > 0`` and the latency posterior
    only when latency samples are present; zero-information parts are left untouched.
    """
    la, lb, n_loss = st.loss_alpha, st.loss_beta, st.n_obs_loss
    if delivered + lost > 0.0:  # Beta-Binomial with exponential forgetting toward the prior
        la = _forget(st.loss_alpha, PRIOR_BETA_ALPHA, rho) + lost
        lb = _forget(st.loss_beta, PRIOR_BETA_BETA, rho) + delivered
        n_loss += 1
    mu, kappa, a, b = st.ng_mu, st.ng_kappa, st.ng_alpha, st.ng_beta
    n = len(lats)
    if n:  # Normal-Gamma conjugate update (same forgetting on kappa, a, b; mu is kept)
        kappa = _forget(st.ng_kappa, PRIOR_NG_KAPPA, rho)
        a = _forget(st.ng_alpha, PRIOR_NG_ALPHA, rho)
        b = _forget(st.ng_beta, PRIOR_NG_BETA, rho)
        xbar = sum(lats) / n
        ss = sum((x - xbar) ** 2 for x in lats)
        kappa_n = kappa + n
        mu_n = (kappa * mu + n * xbar) / kappa_n
        a_n = a + n / 2.0
        b_n = b + 0.5 * ss + kappa * n * (xbar - mu) ** 2 / (2.0 * kappa_n)
        mu, kappa, a, b = mu_n, kappa_n, a_n, b_n
    return replace(st, loss_alpha=la, loss_beta=lb, ng_mu=mu, ng_kappa=kappa, ng_alpha=a,
                   ng_beta=b, last_t_us=max(st.last_t_us, t_us),
                   n_obs_loss=n_loss, n_obs_lat=st.n_obs_lat + (1 if n else 0))


def _update_element(st: ElementState, delivered: float, lost: float, lats: Sequence[float],
                    t_us: int, gamma: float, rho: float,
                    pool: Optional[ElementState] = None) -> ElementState:
    """Posterior update, then CUSUM against the element's own (or the pooled) baseline."""
    new = _posterior_step(st, delivered, lost, lats, t_us, rho)
    n = len(lats)
    pooled = pool is not None
    clp, cln, base_loss = st.cusum_loss_pos, st.cusum_loss_neg, st.base_loss
    if delivered + lost > 0.0:
        b_loss, n_loss = ((pool.loss_rate, pool.n_obs_loss) if pooled
                          else (st.base_loss, st.n_obs_loss))
        clp, base_loss = _loss_llr_step(clp, delivered + lost, lost, b_loss, n_loss,
                                        new.loss_rate, gamma, pooled)
    base_lat, cap, can = st.base_lat, st.cusum_lat_pos, st.cusum_lat_neg
    if n:
        b_lat, n_lat = (pool.latency_mean, pool.n_obs_lat) if pooled else (st.base_lat, st.n_obs_lat)
        if pooled and pool.n_obs_lat == 0:
            b_lat = None
        cap, can, base_lat = _track(cap, can, new.latency_mean, b_lat, n_lat,
                                    K_CUSUM_LATENCY_US, gamma, pooled)
    return replace(new, base_loss=base_loss, base_lat=base_lat, cusum_loss_pos=clp,
                   cusum_loss_neg=cln, cusum_lat_pos=cap, cusum_lat_neg=can)


def update(state: InferState, samples: Iterable[Sample], path_to_links: Dict[str, List[str]],
           baseline_gamma: float = BASELINE_GAMMA, forget_rho: float = FORGET_RHO,
           baseline_mode: str = BASELINE_MODE) -> InferState:
    """Absorb one epoch of samples and return the new state (the input is not mutated).

    Args:
        state: Previous state.
        samples: Sample records of this epoch (any arm, any adapter).
        path_to_links: Known path -> ordered list of link element ids, used for uniform-prior
            de-aggregation of ``path:*`` samples.
        baseline_gamma: EMA rate of the running baseline (frozen default).
        forget_rho: Posterior discount factor per observed epoch (frozen default).
        baseline_mode: ``"per_element"`` (each element's own running baseline) or
            ``"pooled"`` (fabric-wide pooled baseline over atomic elements); frozen default.

    Returns:
        A new :class:`InferState`; elements absent from ``samples`` are carried unchanged.
    """
    if baseline_mode not in BASELINE_MODES:
        raise ValueError("baseline_mode must be one of %s" % (BASELINE_MODES,))
    acc, lats, t_max = _deaggregate(samples, path_to_links)
    # drop zero-information elements: no counts and no latency samples -> not probed
    acc = {e: dl for e, dl in acc.items() if dl[0] + dl[1] > 0.0 or lats[e]}
    pool = state.pool
    if baseline_mode == "pooled" and acc:
        atomic = [e for e in acc if not e.startswith("path:")]
        pool = _posterior_step(pool, sum(acc[e][0] for e in atomic),
                               sum(acc[e][1] for e in atomic),
                               [x for e in atomic for x in lats[e]],
                               max(t_max[e] for e in atomic) if atomic else 0, forget_rho)
    elements = dict(state.elements)
    for element in sorted(acc):  # sorted -> deterministic iteration regardless of input order
        delivered, lost = acc[element]
        elements[element] = _update_element(elements.get(element, ElementState()), delivered,
                                            lost, lats[element], t_max[element], baseline_gamma,
                                            forget_rho, pool if baseline_mode == "pooled" else None)
    logger.debug("infer.update epoch=%d elements=%d mode=%s", state.epoch + 1, len(acc),
                 baseline_mode)
    return InferState(elements=elements, epoch=state.epoch + 1, pool=pool)


# --------------------------------------------------------------------------------------------
# Ranking
# --------------------------------------------------------------------------------------------
def localize(state: InferState, k: int = 1, h: float = H_DEFAULT,
             exclude_prefixes: Tuple[str, ...] = ("path:",),
             min_observations: int = ALARM_MIN_OBS) -> Localization:
    """Rank elements by CUSUM statistic and emit the anomaly bit and top-``k`` suspects.

    Args:
        state: Current localizer state.
        k: Size of the suspect list (PREREG section 2.1: 1 for single fault, |F| otherwise).
        h: CUSUM threshold; the anomaly bit is ``top statistic > h``.  The only per-arm knob
            (PREREG section 3.3, false-alarm operating point).
        exclude_prefixes: Composite elements excluded from the ranking (paths are kept as
            elements for the reward's ``C_p`` but a suspect is an atomic element).
        min_observations: An element can raise the alarm only after this many observations
            (frozen default ``alarm_min_observations``); the ranking itself is unaffected.
    """
    ranked = sorted(
        ((e, st.cusum) for e, st in state.elements.items()
         if not e.startswith(exclude_prefixes) and (st.n_obs_loss or st.n_obs_lat)),
        key=lambda es: (-es[1], -state.elements[es[0]].loss_mean, es[0]),
    )
    anomaly = any(stat > h and state.elements[e].n_obs_loss >= min_observations
                  for e, stat in ranked)
    return Localization(anomaly=anomaly, ranked=ranked, suspects=[e for e, _ in ranked[:k]])


def loss_posterior_var(state: InferState, element: str) -> float:
    """Posterior variance of ``element``'s loss estimate (prior variance if unobserved)."""
    return state.get(element).loss_var


def module_hash() -> str:
    """SHA-256 of this file's source text, for the manifest check against ``frozen.yaml``."""
    with open(os.path.abspath(__file__), "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()
