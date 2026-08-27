# nic/ — host and SmartNIC side (Vision + Hulk)

## Direct link (no switch needed)
- Vision `enp175s0np1s0` (Agilio CX lane, NM profile `smartnic-test`) = 192.168.100.1/24
- Hulk   `enp59s0f1np1`  (XXV710, 10 G)                              = 192.168.100.2/24
- Agilio now at PCI af:00.0 (moved from 3b:00.0); lanes renamed enp175s0np{0,1}s{0-3}.

## Soft-RoCE bring-up (done 2026-08-25; re-run after reboot — not persistent yet)
```bash
sudo modprobe rdma_rxe
sudo rdma link add rxe0 type rxe netdev <iface>
sudo apt-get install -y perftest ibverbs-utils rdma-core
rdma link            # expect: rxe0/1 state ACTIVE physical_state LINK_UP
```

## Smoke test
Hulk (server): `ib_write_bw -d rxe0 -F -s 65536 -n 2000 --report_gbits`
Vision (client): `ib_write_bw -d rxe0 -F -s 65536 -n 2000 --report_gbits 192.168.100.2`

## Agilio firmware modes (verified 2026-08-25)
- Board AMDA0097-0001, lane mode 8x10; active image: `/lib/firmware/netronome/pci-0000:af:00.0.nffw.zst -> nic/nic_AMDA0097-0001_8x10.nffw.zst` (CoreNIC).
- **eBPF-offload image present:** `/lib/firmware/netronome/bpf/nic_AMDA0097-0001_8x10.nffw.zst` (also 2x40, 4x10_1x40).
  Switch: repoint the pci symlink to `bpf/...8x10`, `modprobe -r nfp && modprobe nfp`, verify `ethtool -i` and
  `bpftool feature probe dev <lane>` shows offload; XDP programs then load with `xdpdrv`/`xdpoffload`.
  Note: rxe0 must be re-added after any nfp reload. `~/nfp-fw.sh` (decps) supports only `nic`/`flower`.

---

## `evidence_probe.py` — the NIC-side evidence producer (added 2026-08-27)

`evidence_probe.py` is the host-software half of the MCP evidence loop: design doc
§6 alternative **D1**, PREREG §9.2 Tier-2 NIC arm. It closes the gap that blocked
H7 for fault F1 — the switch has always had the *consumer* (`evid_h`, the parser
state, `tbl_exceed_evid`, `tbl_evid_fwd`), but nothing measured real loss and emitted
evidence.

It runs on **Vision** only. Hulk is not cabled to the switch, so Vision is both the
sender and the receiver: every probe is hairpinned by the fabric (leaf 0 → spine s →
leaf d → back to dp9) and returns to the same interface.

```
sudo ./evidence_probe.py --dst 10.0.1.2 --pps 10000 --duration 30 --csv run.csv
./evidence_probe.py --dry-run          # path map + quantiser table, no root, no sockets
```

It needs **no controller and no bfrt connection**. It is restartable: all state is in
memory and a fresh run re-derives everything.

### What it does

1. **Probes.** A steady stream of sequenced UDP probes to `10.0.1.2` (repeat `--dst`
   for `.3`/`.4`), cycling `--sports` source ports so the switch's hash spray covers
   both spines. Each probe carries its path id, a per-path sequence number and a
   transmit timestamp, in a 35-byte payload that keeps the frame at 77 bytes — the
   same framing as `p4/control`'s test senders.
2. **Measures**, per path: loss from sequence gaps over a sliding window of `W`
   retired probes, RTT from the echoed transmit timestamp, and out-of-order arrivals.
3. **Emits evidence.** Every `--window-ms` (default 10 ms) per path it quantises to
   the 8-bit fields of `evid_h` and sends one evidence packet to UDP port
   `0xE5E5` (58853). The switch's ingress parses it, `tbl_exceed_evid` decides
   whether it is an exceedance, `reg_attn` moves, and `tbl_evid_fwd` forwards the
   packet to a loop port so the *other* pipe's register is updated too before it is
   dropped.
4. **Logs** every window to CSV.

### The part that had to be measured: recovering the path

A delivered frame has no fabric shim — the destination leaf strips it — so the probe
cannot read the spray index off the wire. It recomputes the switch's decision:

```python
spray   = zlib.crc32(src_ip_be + dst_ip_be + sport_be) & 1
path_id = leaf(dst_ip) * 2 + spray
```

`mcp_fabric.p4`'s `CRCPolynomial(0x04C11DB7, reversed=true, init=xor=0xFFFFFFFF)` with
`Hash<bit<16>>` is exactly the standard reflected CRC-32 (`zlib.crc32`) truncated to
its low 16 bits, and with two spines the mask keeps only bit 0.

**This was validated against silicon before the file was trusted**, by capturing
mirrored copies — which carry both `mirror_h.path_id` and the inner UDP source port —
and comparing every one:

| destination | leaf | source ports checked | mismatches | paths seen |
|---|---|---|---|---|
| 10.0.1.2 | 1 | 2994 | **0** | 2, 3 |
| 10.0.1.3 | 2 | 1989 | **0** | 4, 5 |

4983 of 4983 correct. The mapping is a property of the **compiled binary**, not of the
protocol: re-validate it if the hash instance, its field list, or the spine count ever
changes. The capture-and-compare recipe is in the module docstring.

### Quantisers

| field | rule | examples |
|---|---|---|
| `loss_q` | `min(255, int(loss_fraction * 2550 + 0.5))` | 1e-3 → 3, 1e-2 → 26, ≥0.1 → 255 |
| `rtt_q` | `min(255, int(mean_rtt_us / 4))` | 4 µs → 1, 100 µs → 25, ≥1020 µs → 255 |
| `ecn_q` | 0 | no ECN feedback yet |
| `flags` | bit0 = reorder seen | ignored by the switch |

`setup_attention.py up` installs `tbl_exceed_evid` as `loss_q >= 1 OR rtt_q >= 255`,
so in practice **loss raises attention and RTT is carried but inert**. The default
emit rule (`--emit-on any`) sends a packet whenever `loss_q` or `rtt_q` is non-zero;
since the measured RTT through the hairpin is ~220 µs, `rtt_q` is always non-zero and
that means "every window". Use `--emit-on loss` to emit only on loss.

### Measured behaviour on the testbed

Vision → fabric → Vision, 10 000 pps, two paths, 10 ms windows:

- **No fault:** 80 000 sent, 80 000 received, `loss_q = 0` in every window, 0 socket
  drops. Mean RTT ≈ 225 µs (dominated by the host's own send/receive path, not the
  fabric).
- **1 % drop injected on the uplink of path 2** (`setup_skeleton.py fail 0 1 drop`):
  path 2 reported `loss_q > 0` in 894 of 2200 windows (peak 48), while **path 3
  reported `loss_q = 0` in all 2200 windows**. Switch-side, `reg_attn[2]` went
  4096 → **65535 in both pipes** while `reg_attn[3]` only decayed. End-to-end loss
  414 of 220 000 sent, against 400 predicted from the injection rate and the fault
  window.

Two things worth knowing before reading the numbers:

- **Reorder is a host artefact.** ~500 source ports per path means the NIC's RSS
  spreads a path's probes over several receive queues, so userspace sees them
  interleaved: a zero-loss run still reports ~17 500 "reorder" events. It is a
  diagnostic of the receive path, not a fabric measurement.
- **Fake loss is the failure mode to guard against.** If the Python receive loop
  falls behind, dropped packets look exactly like fabric loss. Two defences are
  built in: a classic-BPF filter attached to the receive socket so the kernel only
  queues our own probe replies, and per-window `PACKET_STATISTICS` polling that logs
  `sock_drops` to the CSV. **A window with `sock_drops > 0` should be discarded.**
  Every run reported here had `sock_drops = 0`.

### CSV columns

`wall, path_id, dst_ip, retired, recv, lost, loss_frac_window, loss_q, rtt_mean_us,
rtt_min_us, rtt_max_us, rtt_q, reorder_total, sock_drops, emitted, evid_seq`

### Known limitation in the switch, not here

A mirrored copy **of an evidence packet** carries `mirror_h.path_id = 0` and
`vlink = 0` regardless of which path the evidence was about, because evidence packets
are handled by `tbl_evid_fwd` instead of `tbl_final`, so `hdr.fabric` is never made
valid and the deparser reads zeros out of it. The attention update itself is correct —
the gate reads the right register slot — only the *label on the copy* is wrong. Any
collector-side analysis must therefore identify evidence copies by their inner UDP
destination port (58853) and exclude them from per-path statistics; see
`p4/reports/h7-timing-F1.md`.
