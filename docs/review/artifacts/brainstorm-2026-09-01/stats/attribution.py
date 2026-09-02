"""Section 5: attribution entropy -- bits of link identity per lost packet, and packets to attribution."""
import numpy as np
from scipy.stats import norm

rng = np.random.default_rng(1)
ALPHA = 0.05; LOG_THR = np.log(1 / ALPHA)
n_links = 1024      # candidate directed links (uniform prior on f)
k_paths = 64        # paths a destination can distinguish (SprayCheck-style Z-test)


def h2(q):
    q = np.clip(q, 1e-300, 1 - 1e-16)
    return -(q * np.log2(q) + (1 - q) * np.log2(1 - q))


print("SECTION 5: attribution entropy, n=1024 links, alpha=0.05")
for p, p0 in [(1e-3, 1e-5), (1e-4, 1e-5), (1e-3, 0.0), (1e-4, 0.0)]:
    # (a) witness: per packet (link label e, loss bit Z). Mutual information I(f; (e,Z)) per packet
    #     = h(mean loss) - avg conditional entropy ; divide by expected losses per packet -> bits per lost packet
    pbar = (p + (n_links - 1) * p0) / n_links
    I_pkt = h2(pbar) - ((1 / n_links) * h2(p) + ((n_links - 1) / n_links) * h2(p0))
    bits_per_loss_a = I_pkt / pbar
    # packets to alpha-valid attribution: d* drops on the faulty link, each drop worth log2(p/p0) bits of LLR
    if p0 > 0:
        d_star = np.ceil(LOG_THR / np.log(p / p0)); packets_a = d_star / p
    else:
        d_star = 1; packets_a = 1 / p
    # (b) Z-test at the destination on k path counts (each path carries m/k packets): shift p*m/k vs sd sqrt(m/k)
    z = norm.isf(ALPHA / k_paths)            # Bonferroni over the k paths, one-sided
    m_b = k_paths * (z + norm.isf(0.2)) ** 2 / p ** 2   # power 0.8
    # information about f per lost packet: Gaussian channel, I ~ (1/2) log2(1 + snr) per path-window
    # with L = p m / k lost packets; snr = p^2 m / k  => bits per lost packet ~ p / (2 ln 2) for small snr
    bits_per_loss_b = p / (2 * np.log(2))
    print(f"\n p={p:g} p0={p0:g}")
    print(f"  (a) witness : I(f;(e,Z)) per packet = {I_pkt:.3e} bits -> {bits_per_loss_a:6.2f} bits per lost packet "
          f"(log2 n = {np.log2(n_links):.1f}; LLR per drop = log2(p/p0) = {np.log2(p/p0) if p0>0 else np.inf:.2f});  packets on f to alarm = {packets_a:,.0f} (d*={d_star:.0f})")
    print(f"  (b) Z-test  : ~{bits_per_loss_b:.2e} bits per lost packet;  packets sprayed to detect (k={k_paths}, z_Bonf={z:.2f}, power .8) = {m_b:,.0f}  -> ratio (b)/(a) = {m_b/packets_a:,.0f}x")
    for B_frac in (0.01, 0.04):
        # (c) uniform probing at budget B = B_frac * n probes per epoch spread over n links: each link sees B_frac probes/epoch
        # info per epoch = B_frac * (p/1) * bits_per_loss ; epochs to d* drops on f = d*/(B_frac*p)
        print(f"  (c) probing : budget {B_frac:.0%} of links per epoch, 1 probe each -> epochs to attribution = {d_star/(B_frac*p):,.0f} (vs witness {d_star/p:,.0f} production packets on f)")

# quick Monte Carlo check of (b): destination Z-test with k=64 paths, m packets, faulty path loses p=1e-3
p = 1e-3; k = 64
for m in (int(1e7), int(6e8)):
    per_path = m // k
    hits = 0; trials = 200
    for _ in range(trials):
        tx = rng.multinomial(m, np.full(k, 1.0 / k))          # destination does NOT see this
        cnt = rng.binomial(tx, 1 - np.where(np.arange(k) == 0, p, 0.0))   # it sees only arrivals
        zsc = (cnt.mean() - cnt) / np.sqrt(cnt.mean())          # spray noise ~ Poisson(m/k)
        hits += (zsc.argmax() == 0) and (zsc.max() > norm.isf(ALPHA / k))
    print(f"  MC (b): m={m:.0e} sprayed packets, k={k}: detect+localise faulty path {hits/trials:.0%}")
