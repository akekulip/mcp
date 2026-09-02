"""Fleet-level false-discovery control across sublinks (e-BH, Wang & Ramdas 2022).

Given one e-value per currently-active sublink, decide which subset can be
flagged while controlling the expected fraction of false discoveries at level
alpha -- with no independence or distributional assumption on the e-values
beyond E[e] <= 1 under each null, which every e-process in this project
already guarantees by construction. `docs/review/BRAINSTORM-2026-09-01.md` C2:
"Fleet-level control with e-BH across 1024 sublinks."

Procedure: sort e-values descending; k* = max{k : e_(k) >= n/(k*alpha)}; reject
the top k* sublinks (or none, if no such k exists).
"""

from typing import Dict, FrozenSet


def e_bh_reject(evalues: Dict[int, float], alpha: float) -> FrozenSet[int]:
    if not 0.0 < alpha < 1.0:
        raise ValueError("alpha must lie in (0, 1)")
    if any(value < 0.0 for value in evalues.values()):
        raise ValueError("e-values must be non-negative")
    n = len(evalues)
    if n == 0:
        return frozenset()

    ordered = sorted(evalues.items(), key=lambda item: item[1], reverse=True)
    threshold_k = 0
    for k, (_, value) in enumerate(ordered, start=1):
        if value >= n / (k * alpha):
            threshold_k = k
    return frozenset(sublink for sublink, _ in ordered[:threshold_k])
