"""Sequential-design simulations for the MCP advisory (sections 1, 2, 3, 6)."""
import numpy as np
from scipy.special import logsumexp

rng = np.random.default_rng(20260901)
ALPHA = 0.05
LOG_THR = np.log(1 / ALPHA)


def kl(p1, p0):
    return p1 * np.log(p1 / p0) + (1 - p1) * np.log((1 - p1) / (1 - p0))


# ---------------------------------------------------------------- section 1
def run_absolute(p_true, p0, n_epoch, horizon, runs, grid, six_alt=None):
    """One-sided binomial e-processes against packetwise null loss <= p0.

    Arms: oracle SPRT at p_true; log-uniform grid mixture; KT plug-in (GRO-style);
    optionally the repo's six-alternative mixture against delivery >= 0.99.
    Returns dict arm -> (alarm_rate, mean_packets_to_alarm_given_alarm)
    """
    lw = np.log(np.ones(len(grid)) / len(grid))
    log_grid = np.zeros((runs, len(grid)))
    log_or = np.zeros(runs)
    log_kt = np.zeros(runs)
    D = np.zeros(runs); N = np.zeros(runs)
    p_or = max(p_true, p0 * 1.0000001)
    a_or = np.full(runs, np.inf); a_grid = np.full(runs, np.inf); a_kt = np.full(runs, np.inf)
    if six_alt is not None:
        log_six = np.zeros((runs, len(six_alt)))
        a_six = np.full(runs, np.inf)
    for t in range(1, horizon + 1):
        L = rng.binomial(n_epoch, p_true, size=runs)
        S = n_epoch - L
        # KT plug-in uses the estimate BEFORE this epoch (predictable), clipped to >= p0
        p_hat = np.maximum((D + 0.5) / (N + 500.0), p0)   # Beta(0.5,500) plug-in: prior mean 1e-3
        log_kt += L * np.log(p_hat / p0) + S * np.log((1 - p_hat) / (1 - p0))
        D += L; N += n_epoch
        log_or += L * np.log(p_or / p0) + S * np.log((1 - p_or) / (1 - p0))
        log_grid += L[:, None] * np.log(grid / p0)[None, :] + S[:, None] * np.log((1 - grid) / (1 - p0))[None, :]
        e_grid = logsumexp(log_grid + lw[None, :], axis=1)
        pk = t * n_epoch
        a_or = np.where((a_or == np.inf) & (log_or >= LOG_THR), pk, a_or)
        a_grid = np.where((a_grid == np.inf) & (e_grid >= LOG_THR), pk, a_grid)
        a_kt = np.where((a_kt == np.inf) & (log_kt >= LOG_THR), pk, a_kt)
        if six_alt is not None:
            # repo ledger: delivery alternatives vs healthy_delivery 0.99
            hd = 0.99
            log_six += S[:, None] * np.log(np.array(six_alt) / hd)[None, :] + L[:, None] * np.log((1 - np.array(six_alt)) / (1 - hd))[None, :]
            e_six = logsumexp(log_six + np.log(1 / len(six_alt)), axis=1)
            a_six = np.where((a_six == np.inf) & (e_six >= LOG_THR), pk, a_six)
    out = {}
    for name, a in [("oracle-SPRT", a_or), ("log-uniform mixture", a_grid), ("Beta(.5,500) plug-in", a_kt)] + ([("repo six-alt vs 0.99", a_six)] if six_alt is not None else []):
        hit = a < np.inf
        out[name] = (hit.mean(), a[hit].mean() if hit.any() else float("nan"), np.median(a[hit]) if hit.any() else float("nan"))
    return out


def section1():
    print("=" * 78)
    print("SECTION 1: absolute one-sided binomial e-processes, null loss <= p0")
    p0 = 1e-5
    grid = np.logspace(np.log10(2e-5), -1, 25)
    six = (0.01, 0.10, 0.50, 0.75, 0.90, 0.97)
    for p_true, n_epoch, horizon in [(1e-3, 100, 300), (1e-4, 500, 600), (3e-5, 2000, 2500)]:
        floor = LOG_THR / kl(p_true, p0)
        d_star = np.ceil(LOG_THR / np.log(p_true / p0))
        print(f"\np_true={p_true:g}  p0={p0:g}  epoch={n_epoch}  horizon={n_epoch*horizon:.0f} packets")
        print(f"  Wald info floor ln(1/a)/KL = {floor:,.0f} packets;  1/p = {1/p_true:,.0f};  drops needed d*=ceil(ln(1/a)/ln(p/p0)) = {d_star:.0f}  -> quantised floor d*/p = {d_star/p_true:,.0f}")
        res = run_absolute(p_true, p0, n_epoch, horizon, 2000, grid, six)
        for k, (r, m, md) in res.items():
            print(f"  {k:24s} alarm={r:6.1%}  mean packets={m:>10,.0f}  median={md:>10,.0f}")
    # false alarm under the null at p0 and at a slightly-below floor
    for p_true in (p0, 0.5 * p0):
        res = run_absolute(p_true, p0, 2000, 1000, 2000, grid)
        print(f"\nNULL p_true={p_true:g}, horizon 2e6 packets:  " + ", ".join(f"{k}: FA={r:.2%}" for k, (r, m, md) in res.items()))


# ---------------------------------------------------------------- section 2
def gilbert_elliott(runs, n_pkts, mean_loss, burst_len, reset_each=None, state=None):
    """Per-packet loss indicators from a 2-state chain; bad state drops with prob 1."""
    b = 1.0 / burst_len
    a = b * mean_loss / (1 - mean_loss)
    if state is None:
        state = rng.random(runs) < mean_loss
    out = np.zeros((runs, n_pkts), dtype=bool)
    for i in range(n_pkts):
        if reset_each is not None and i % reset_each == 0 and i > 0:
            state = rng.random(runs) < mean_loss   # guard gap longer than mixing time
        out[:, i] = state
        u = rng.random(runs)
        state = np.where(state, u >= b, u < a)
    return out, state


def epoch_betting(X, p0, lam_c=(0.05, 0.1, 0.2, 0.3, 0.5, 0.7, 0.9)):
    """Mixture of bounded-mean betting e-processes on epoch loss fractions X[runs, epochs].

    W_k = prod (1 + lam (X_k - p0)), lam = c/p0, c<1 so factor > 0. Returns log-wealth path.
    """
    lam = np.array(lam_c) / p0
    fac = 1 + lam[None, None, :] * (X[:, :, None] - p0)
    logw = np.cumsum(np.log(fac), axis=1)
    return logsumexp(logw + np.log(1 / len(lam)), axis=2)


def packetwise_six(L, n, six=(0.01, 0.10, 0.50, 0.75, 0.90, 0.97), hd=0.99):
    S = n - L
    six = np.array(six)
    logw = np.cumsum(S[:, :, None] * np.log(six / hd) + L[:, :, None] * np.log((1 - six) / (1 - hd)), axis=1)
    return logsumexp(logw + np.log(1 / len(six)), axis=2)


def packetwise_grid(L, n, p0, grid):
    S = n - L
    logw = np.cumsum(L[:, :, None] * np.log(grid / p0) + S[:, :, None] * np.log((1 - grid) / (1 - p0)), axis=1)
    return logsumexp(logw + np.log(1 / len(grid)), axis=2)


def first_cross(logE):
    hit = logE >= LOG_THR
    any_hit = hit.any(axis=1)
    first = np.where(any_hit, hit.argmax(axis=1) + 1, np.nan)
    return any_hit.mean(), np.nanmedian(first) if any_hit.any() else float("nan")


def section2():
    print("\n" + "=" * 78)
    print("SECTION 2: bursty loss.  Repo setting n=32/epoch, 50 epochs, null delivery>=0.99, 2000 runs")
    runs, n, H = 2000, 32, 50
    p0 = 0.01
    cases = [("IID loss 0.005", None, 5, False), ("GE mean loss .005, burst 5", None, 5, True),
             ("GE mean loss .005, burst 10", None, 10, True), ("GE .005 burst 10 + guard reset", "guard", 10, True),
             ("IID loss 0.01 (boundary)", None, 5, False)]
    for name, guard, bl, bursty in cases:
        ml = 0.01 if "0.01" in name else 0.005
        if bursty:
            ind, _ = gilbert_elliott(runs, n * H, ml, bl, reset_each=(n if guard else None))
            L = ind.reshape(runs, H, n).sum(axis=2)
        else:
            L = rng.binomial(n, ml, size=(runs, H))
        fa6, _ = first_cross(packetwise_six(L, n))
        fab, _ = first_cross(epoch_betting(L / n, p0))
        print(f"  {name:34s} packetwise six-alt FA={fa6:6.1%}   epoch-level betting FA={fab:6.1%}")
    print("  Power at IID (survival .98 / .985 / .97), same horizon:")
    for pl in (0.02, 0.015, 0.03):
        L = rng.binomial(n, pl, size=(runs, H))
        r6, m6 = first_cross(packetwise_six(L, n)); rb, mb = first_cross(epoch_betting(L / n, p0))
        print(f"    loss {pl:5.3f}: packetwise six-alt power={r6:6.1%} (median epoch {m6}), epoch betting power={rb:6.1%} (median epoch {mb})")
    print("  Target regime: p0=1e-4, epochs of 200 packets, 2500 epochs (5e5 packets), IID p=1e-3:")
    grid = np.logspace(np.log10(2e-4), -1, 20)
    L = rng.binomial(200, 1e-3, size=(1000, 2500))
    rg, mg = first_cross(packetwise_grid(L, 200, 1e-4, grid)); rb, mb = first_cross(epoch_betting(L / 200, 1e-4))
    print(f"    packetwise grid mixture: power={rg:.1%}, median packets={200*mg:,.0f};  epoch betting: power={rb:.1%}, median packets={200*mb:,.0f}")
    print("    (both valid; the epoch-level test pays for burst-robustness in packets)")
    print("  Bursty at target regime: GE mean loss 1e-4 burst 10, 200-pkt epochs, 2000 epochs:")
    ind, _ = gilbert_elliott(1000, 200 * 2000, 1e-4, 10)
    L = ind.reshape(1000, 2000, 200).sum(axis=2)
    rg, _ = first_cross(packetwise_grid(L, 200, 1e-4, grid)); rb, _ = first_cross(epoch_betting(L / 200, 1e-4))
    print(f"    packetwise grid FA={rg:.1%}   epoch betting FA={rb:.1%}")


# ---------------------------------------------------------------- section 3
def section3():
    print("\n" + "=" * 78)
    print("SECTION 3: censoring. p0=1e-4, 200-pkt epochs, grid mixture, 2000 runs")
    grid = np.logspace(np.log10(2e-4), -1, 20)
    runs, n, H = 2000, 200, 1500
    lw = np.log(1 / len(grid))
    for label, p_true in [("NULL p=1e-4", 1e-4), ("ALT p=1e-3", 1e-3)]:
        L = rng.binomial(n, p_true, size=(runs, H))
        inc = L[:, :, None] * np.log(grid / 1e-4) + (n - L)[:, :, None] * np.log((1 - grid) / (1 - 1e-4))
        for cname, cmask in [("no censoring", np.zeros((runs, H), bool)),
                             ("random censor 30% (non-informative)", rng.random((runs, H)) < 0.3),
                             ("censor 50% of CLEAN epochs (informative)", (L == 0) & (rng.random((runs, H)) < 0.5)),
                             ("censor 50% of LOSSY epochs (informative, conservative)", (L > 0) & (rng.random((runs, H)) < 0.5))]:
            # carry: censored epoch contributes factor 1
            inc_c = np.where(cmask[:, :, None], 0.0, inc)
            logE_carry = logsumexp(np.cumsum(inc_c, axis=1) + lw, axis=2)
            r_c, m_c = first_cross(logE_carry)
            # restart: reset capital and spend alpha/2^(k+1)
            hit = np.zeros(runs, bool); first = np.full(runs, np.nan)
            cap = np.zeros((runs, len(grid))); k = np.zeros(runs)
            for t in range(H):
                cm = cmask[:, t]
                cap = np.where(cm[:, None], 0.0, cap + inc[:, t])
                k = k + cm
                thr = np.log(2.0 ** (k + 1) / ALPHA)
                e = logsumexp(cap + lw, axis=1)
                new = (~hit) & (~cm) & (e >= thr)
                first[new] = t + 1; hit |= new
            print(f"  {label:12s} {cname:52s} carry(factor 1): rate={r_c:6.1%} med.epoch={m_c:>6}  | restart(alpha/2^k+1): rate={hit.mean():6.1%} med.epoch={np.nanmedian(first) if hit.any() else float('nan'):>6}")


# ---------------------------------------------------------------- section 6
def section6():
    print("\n" + "=" * 78)
    print("SECTION 6: restoration on probes. p_target=1e-3, alpha=0.05, budget 20000 probes, 2000 runs")
    pt = 1e-3
    N_consec = int(np.ceil(np.log(ALPHA) / np.log(1 - pt)))
    print(f"  repo rule: N = ceil(log(alpha)/log(1-p_t)) = {N_consec} consecutive clean probes")
    cert_alts = np.array([0.0, 1e-4, 2.5e-4, 5e-4])          # null: loss >= p_t
    quar_alts = np.array([2e-3, 5e-3, 1e-2, 5e-2, 0.5])       # null: loss <= p_t
    runs, n, H = 2000, 100, 200
    for p_true in (0.0, 1e-4, 5e-4, 1e-3, 3e-3, 1e-2):
        L = rng.binomial(n, p_true, size=(runs, H)); S = n - L
        with np.errstate(divide="ignore"):
            lc = np.where(cert_alts > 0, np.log(np.maximum(cert_alts, 1e-300) / pt), -np.inf)
        inc_c = np.where(L[:, :, None] > 0, L[:, :, None] * lc[None, None, :], 0.0) + S[:, :, None] * np.log((1 - cert_alts) / (1 - pt))[None, None, :]
        logC = logsumexp(np.cumsum(inc_c, axis=1) + np.log(1 / len(cert_alts)), axis=2)
        inc_q = L[:, :, None] * np.log(quar_alts / pt)[None, None, :] + S[:, :, None] * np.log((1 - quar_alts) / (1 - pt))[None, None, :]
        logQ = logsumexp(np.cumsum(inc_q, axis=1) + np.log(1 / len(quar_alts)), axis=2)
        tc = np.where((logC >= LOG_THR).any(1), (logC >= LOG_THR).argmax(1) + 1, np.inf)
        tq = np.where((logQ >= LOG_THR).any(1), (logQ >= LOG_THR).argmax(1) + 1, np.inf)
        certified = (tc < tq) & (tc < np.inf); requar = (tq <= tc) & (tq < np.inf); incon = ~certified & ~requar
        # consecutive-clean rule: first run of N_consec clean probes within the budget
        ind = rng.random((runs, n * H)) < p_true
        # position of the first window of N_consec consecutive clean packets
        cs = np.cumsum(ind, axis=1)
        cs = np.concatenate([np.zeros((runs, 1), int), cs], axis=1)
        win = cs[:, N_consec:] - cs[:, :-N_consec]          # losses in window ending at i
        ok = win == 0
        cc_hit = ok.any(1); cc_t = np.where(cc_hit, ok.argmax(1) + N_consec, np.inf)
        # consecutive rule with re-quarantine on the same probes
        cc_cert = cc_hit & (cc_t < tq * n)
        print(f"  p_true={p_true:<7g} consecutive-clean: certify={cc_hit.mean():6.1%} med.probes={np.median(cc_t[cc_hit]) if cc_hit.any() else float('nan'):>8,.0f}"
              f" | two-sided e-process: certify={certified.mean():6.1%} (med {np.median(tc[certified])*n if certified.any() else float('nan'):>7,.0f} probes)"
              f" re-quarantine={requar.mean():6.1%} (med {np.median(tq[requar])*n if requar.any() else float('nan'):>7,.0f}) inconclusive={incon.mean():5.1%}")


if __name__ == "__main__":
    import sys
    for sec in sys.argv[1:]: globals()['section'+sec]()
