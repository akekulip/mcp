"""Section 8: peer-relative (sibling-exchangeability) e-process with adaptive spray weights."""
import numpy as np
from scipy.special import logsumexp

rng = np.random.default_rng(20260901)
ALPHA = 0.05; LOG_THR = np.log(1 / ALPHA)
R_GRID = np.array([1.1, 1.25, 1.5, 2, 4, 10, 100, np.inf])   # loss-rate ratio of the suspect vs its siblings


def sibling_eprocess(k, n_epoch, H, runs, q, delta, f=0, adaptive=False, bursty=False, p0_abs=None):
    """Each packet in an epoch is assigned to sibling j w.p. w_j (predictable, fixed within the epoch).

    Null: P(lost | assigned j, past, time) does not depend on j. Then, conditional on the epoch's
    total losses L, the split (L_1..L_k) ~ Multinomial(L, w). E-process component for (suspect j,
    ratio r): prod_i (w'_i / w_i)^{L_i} with w'_j = w_j r / Z, w'_i = w_i / Z, Z = w_j r + 1 - w_j.
    Mixture over j uniform and r uniform on R_GRID.
    """
    nj, nr = k, len(R_GRID)
    logw = np.zeros((runs, nj, nr))
    lprior = np.log(1.0 / (nj * nr))
    w = np.full((runs, k), 1.0 / k)
    alarm_t = np.full(runs, np.inf); alarm_link = np.full(runs, -1)
    abs_alarm = np.full((runs, k), np.inf)
    logabs = np.zeros((runs, k))
    for t in range(1, H + 1):
        TX = rng.multinomial(n_epoch, w[0], size=runs) if not adaptive else np.stack([rng.multinomial(n_epoch, wi) for wi in w])
        rate = np.full(k, q); rate[f] += delta
        if bursty:
            # symmetric bursty background: losses arrive in bursts (Poisson bursts x geometric length),
            # each burst's packets are assigned iid w -> split is multinomial under the null.
            nb = rng.poisson(n_epoch * q / 10.0, size=runs)
            Ltot = np.array([rng.geometric(0.1, size=b).sum() if b > 0 else 0 for b in nb])
            Ltot = np.minimum(Ltot, n_epoch)
            L = np.stack([rng.multinomial(l, wi) for l, wi in zip(Ltot, w)])
        else:
            L = rng.binomial(TX, rate[None, :])
        # --- peer-relative update
        for j in range(k):
            Z = w[:, j][:, None] * R_GRID[None, :] + (1 - w[:, j])[:, None]        # runs x nr
            with np.errstate(divide="ignore", invalid="ignore"):
                lr_j = np.log(np.where(np.isinf(R_GRID)[None, :], 1.0 / w[:, j][:, None], R_GRID[None, :] / Z))  # w'_j/w_j
                lr_o = np.where(np.isinf(R_GRID)[None, :], -np.inf, -np.log(Z))                                    # w'_i/w_i, i != j
            other = L.sum(1) - L[:, j]
            logw[:, j, :] += L[:, j][:, None] * lr_j + np.where(other[:, None] > 0, other[:, None] * lr_o, 0.0)
        e_link = logsumexp(logw + np.log(1.0 / nr), axis=2)          # per-link mixture e-value (over r)
        e_all = logsumexp(e_link + np.log(1.0 / nj), axis=1)
        new = (alarm_t == np.inf) & (e_all >= LOG_THR)
        alarm_t[new] = t; alarm_link[new] = e_link[new].argmax(1)
        # --- absolute detector per sibling (for comparison)
        if p0_abs is not None:
            grid = np.logspace(np.log10(p0_abs * 2), -1, 15)
            inc = L[:, :, None] * np.log(grid / p0_abs) + (TX - L)[:, :, None] * np.log((1 - grid) / (1 - p0_abs))
            logabs = logabs if logabs.ndim == 3 else np.zeros((runs, k, len(grid)))
            logabs = logabs + inc
            ea = logsumexp(logabs + np.log(1 / len(grid)), axis=2)
            abs_alarm = np.where((abs_alarm == np.inf) & (ea >= LOG_THR), t, abs_alarm)
        # --- adaptive weights for the NEXT epoch: predictable function of wealth so far
        if adaptive:
            shrink = np.minimum(1.0, 4.0 / np.exp(np.clip(e_link, 0, 50)))     # suspect with e>4 gets less traffic
            wn = shrink / shrink.sum(1, keepdims=True)
            w = np.maximum(wn, 0.05); w = w / w.sum(1, keepdims=True)
    return alarm_t, alarm_link, abs_alarm


def summarize(tag, alarm_t, alarm_link, f, n_epoch, abs_alarm=None, k=2):
    hit = alarm_t < np.inf
    med = np.median(alarm_t[hit]) * n_epoch if hit.any() else float("nan")
    correct = (alarm_link == f)[hit].mean() if hit.any() else float("nan")
    s = f"  {tag:46s} alarm={hit.mean():6.1%}  median packets(total)={med:>10,.0f}  named faulty sibling={correct:5.1%}"
    if abs_alarm is not None:
        s += f" | absolute: faulty={np.isfinite(abs_alarm[:, f]).mean():5.1%}, healthy sibling={np.isfinite(abs_alarm[:, 1 - f]).mean():5.1%}"
    print(s)


if __name__ == "__main__":
    k, n, H, runs = 2, 1000, 800, 1000
    print("SECTION 8: k=2 siblings, 1000 packets/epoch total, horizon 8e5 packets, alpha=0.05, 1000 runs")
    print("Validity under the null (no excess loss), symmetric background:")
    for q, bursty in [(1e-3, False), (1e-2, False), (1e-2, True)]:
        a, l, _ = sibling_eprocess(k, n, H, runs, q, 0.0, bursty=bursty)
        summarize(f"null q={q:g} {'bursty' if bursty else 'iid'} equal weights", a, l, 0, n)
        a, l, _ = sibling_eprocess(k, n, H, runs, q, 0.0, adaptive=True, bursty=bursty)
        summarize(f"null q={q:g} {'bursty' if bursty else 'iid'} ADAPTIVE weights", a, l, 0, n)
    print("Power at excess delta=1e-3 on sibling 0; absolute detector shown with p0=1e-5 and p0=2e-2:")
    for q in (0.0, 1e-3, 1e-2):
        for p0 in (1e-5, 2e-2):
            a, l, ab = sibling_eprocess(k, n, H, runs, q, 1e-3, p0_abs=p0)
            summarize(f"bg q={q:g}, equal weights, abs p0={p0:g}", a, l, 0, n, ab)
        a, l, _ = sibling_eprocess(k, n, H, runs, q, 1e-3, adaptive=True)
        summarize(f"bg q={q:g}, ADAPTIVE weights", a, l, 0, n)
    for q in (0.0, 1e-3, 1e-2):
        d = 1e-3; s = (q + d) / (2 * q + d) if q > 0 else 1.0
        klb = (s * np.log(2 * s) + (1 - s) * np.log(2 * (1 - s))) if q > 0 else np.log(2)
        losses = LOG_THR / klb; pk = losses / (q + d / 2)
        print(f"  analytic q={q:g}: share of losses on faulty={s:.3f}, KL/loss={klb:.4f} nats -> ~{losses:.0f} losses ~ {pk:,.0f} packets total")
