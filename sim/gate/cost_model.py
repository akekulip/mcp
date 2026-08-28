#!/usr/bin/env python3
"""cost_model.py — put every measurement mechanism on the PREREG §2.3 axes, from recorded traffic.

The point of this file is that a scheduled-counter arm and an in-band witness DO NOT SPEND THE
SAME CURRENCY, so "equal cost" cannot be asserted by matching one number. §2.3 defines five units;
the two mechanisms load different ones:

  * scheduled counter reading spends **control-plane reads/s** and buys coverage delay;
  * an in-band witness spends **wire bytes on every production packet** (beta_tag) and buys
    coverage delay of zero, with no scheduled reads at all.

So the frontier is a plane, not a line, and this script computes both coordinates from the
recorded per-link counter logs rather than from assumptions about offered load.

WHAT IS MEASURED HERE vs WHAT IS CITED. The traffic (packets/s per link, fabric capacity) is
measured from the logs. The per-mechanism costs are: OUR witness -- the header width is our design
and the compiled resource delta is in p4/witness/COMPILE-GATE.md; NetSeer and alternate marking --
published figures, cited, not reimplemented. Detection delay comes from replay.py.

Usage:  ./cost_model.py --results results_real_v12/moe8x8b_n16/uniform [--mtu 1500] [--link-gbps 200]
"""
import argparse
import collections
import csv
from pathlib import Path

EPOCH_S = 0.1


def carried(counters: Path):
    """-> (n_links, epochs, total tx packets across all links) from one recorded run."""
    per_epoch = collections.defaultdict(dict)
    with open(counters) as f:
        for r in csv.DictReader(f):
            per_epoch[int(r["epoch"])][r["link_name"]] = int(r["tx"])
    last = per_epoch[max(per_epoch)]
    return len(last), len(per_epoch), sum(last.values())


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--results", required=True)
    ap.add_argument("--mtu", type=int, default=1500)
    ap.add_argument("--link-gbps", type=float, default=200.0)
    ap.add_argument("--budget", type=int, default=41, help="links read per epoch by the scheduled arm")
    a = ap.parse_args()

    runs = sorted(Path(a.results).glob("seed*.counters.csv"))
    if not runs:
        raise SystemExit("no counter logs in %s" % a.results)
    n_links, epochs, pkts = carried(runs[0])
    dur = epochs * EPOCH_S
    pps = pkts / dur
    cap_bps = n_links * a.link_gbps * 1e9
    carried_bps = pps * a.mtu * 8

    def pct_cap(bytes_per_s):
        return 100.0 * bytes_per_s * 8 / cap_bps

    tag_bps = pps * 4                       # 4 witness bytes on every production packet
    print(f"# cost model from {runs[0].name}: {n_links} links, {epochs} epochs ({dur:.1f} s)")
    print(f"# carried {pps:,.0f} pkt/s = {carried_bps/1e12:.3f} Tb/s at {a.mtu} B MTU; "
          f"fabric capacity {cap_bps/1e12:.1f} Tb/s ({n_links} x {a.link_gbps:.0f}G)")
    print(f"# fabric utilisation on this trace: {100*carried_bps/cap_bps:.2f} %\n")

    rows = [
        # name, beta_probe %, beta_tag %cap, tag % of carried, control reads/s, coverage epochs, source
        ("scheduled counters, B=41 (uniform)", 0.0, 0.0, 0.0,
         a.budget / EPOCH_S, "11.0", "measured (replay)"),
        ("scheduled counters, B=n (in-band stand-in)", 0.0, 0.0, 0.0,
         n_links / EPOCH_S, "1.0", "measured (replay)"),
        ("W4 order witness (ours, 4 B)", 0.0, pct_cap(tag_bps), 100.0 * 4 / a.mtu,
         0.0, "1.0 by construction", "bytes measured, delay not yet on silicon"),
        ("NetSeer inter-switch detection (4 B)", 0.0, pct_cap(tag_bps), 100.0 * 4 / a.mtu,
         0.0, "1.0 by construction", "SIGCOMM'20 §3.3, published"),
        ("RFC 9341 alternate marking, 100 ms colour", 0.0, 0.0, 0.0,
         2 * n_links / EPOCH_S, ">= colour period", "RFC 9341, published"),
    ]
    print("| mechanism | beta_probe | beta_tag (% capacity) | tag as % of carried bytes | "
          "control reads/s | coverage delay | provenance |")
    print("|---|---|---|---|---|---|---|")
    for nm, bp, bt, tc, rd, cov, src in rows:
        print(f"| {nm} | {bp:.3f} % | {bt:.4f} % | {tc:.3f} % | {rd:,.0f} | {cov} | {src} |")

    reads_n = n_links / EPOCH_S
    print(f"\nReading: the witness and the scheduled arms are NOT on one axis. The witness buys "
          f"coverage delay 0 for ~{pct_cap(tag_bps):.4f} % of fabric capacity and NO scheduled "
          f"reads; the B=n stand-in buys the same delay for zero wire bytes but {reads_n:,.0f} "
          f"reads/s, {n_links / a.budget:.0f}x the B=41 arm. Any 'equal cost' claim has to say "
          f"which currency it equalises.")
    print("NOT PRICED HERE: per-link witness state and MAU stages (p4/witness/COMPILE-GATE.md), "
          "exception-report bytes (one per loss event), collector CPU, and NetSeer's ring buffer "
          "plus its 3 redundant notification packets per loss event.")


if __name__ == "__main__":
    main()
