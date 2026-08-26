# HURDLES — known risks, mitigations, and the test that closes each

| # | Hurdle | Mitigation | Closed by | Status |
|---|---|---|---|---|
| H1 | 12 MAU stages; hop-fwd + spray + counters + drop + INT + attention gate may not fit | Single `vlink_id` index computed once; range tables for compares; INT insertion in egress only; compiler resource report | S-DOWN compile | open |
| H2 | Recirc bandwidth: H hops × 35 G host ingress | dp68 + spare ports in MAC-near loopback; cap H ≤ 4 for host traffic; pktgen for stress | S-DOWN design, S-UP measure | open |
| H3 | Max 4 RegisterActions/Register; 32-bit SALU; no var-vs-var `if` | Split state; range keys; widen flags to bit<8> | S-DOWN compile | open |
| H4 | No TNA INT/qdepth precedent locally; PHV budget | Fixed 8–12 B CSIG-style compare-and-replace tag, not INT stack | S-DOWN compile + PTF | open |
| H5 | Mirror session count / truncation on 9.13.2 | `$max_pkt_len` code from defense4; one session per attention class | S-DOWN scripts, S-UP verify | open |
| H6 | rxe single-core ceiling; no DCQCN/PFC | Many QPs + netns; state lossy/software-RDMA; DPDK generator | S-DOWN on Agilio↔Hulk link | open |
| H7 | Agilio PCIe x4 (31.5 G), 10 G lanes; SDK absent (verified 2026-08-25: no /opt/netronome, no p4c-nfp; `nfp` driver loaded, device 4000, lanes enp175s0np{0,1}s{0-3}) | XDP (NFP offload if firmware allows, else host XDP); RTT via host XDP | S-DOWN on Vision | decided: XDP — bpf-offload firmware present on Vision (nic/README.md) |
| H8 | Single TM ⇒ no cross-switch skew | State in paper; sim tier covers | — | accepted |
| H9 | Sim→HW gap | Calibrate htsim with measured RTT / counter-read latency; KS distance | S-DOWN partial, S-UP | open |
| H10 | Loopback-mode change silently rejected on live entry | DELETE-then-add | S-UP | open |
| H11 | bf_switchd exits on stdin EOF; LD_LIBRARY_PATH | `launch_switchd.sh` | S-UP | open |
| H12 | Shared chip (`defense4_caseA` loaded) | tofino-p4 shared-chip rules; schedule windows | S-UP | open |
| H13 | Reward leakage / non-stationarity | Observation-only reward + unit test; discounted UCB baseline | S-DOWN sim | open |
| H14 | Stale skill facts (switch IP .15 → .81) | Updated tofino-p4 skill + lab-servers memory 2026-08-25 | S-DOWN | closed |
| H15 | Deadline | SIGCOMM'27 confirmed by Philip 2026-08-25; CFP not yet out, assume ~late Jan 2027 by '26 pattern — re-verify monthly | M0 | closed |
| H16 | Hosts lack `rdma_rxe`, perftest, DPDK (verified 2026-08-25; libibverbs 50.0 present, kernel 6.8, bpftool present) | `modprobe rdma_rxe` + `rdma link add` + apt perftest/dpdk — needs sudo on shared lab servers → get Philip's go-ahead | S-DOWN | approved 2026-08-25, in progress |
