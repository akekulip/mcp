"""Faithful replay implementations of published competing detectors.

Each module here reimplements ONE paper's own passive-counter algorithm, from
its own equations, over the same per-sublink counter format the rest of the
repo uses (`sim/gate/replay.py`'s cumulative `(tx, rx, drop)` per epoch). They
are baselines, not our mechanism: each is deliberately restricted to the
observations that paper's real switch would have (e.g. SprayCheck never sees
TX or drop directly, only RX-side arrival counts for one measured flow).

See `sim/baselines/tests/` for the fidelity checks against each paper's own
published operating points, and each module's docstring for the primary
source, the exact equation implemented, and any judgment call made where the
paper does not fully specify a constant.
"""
