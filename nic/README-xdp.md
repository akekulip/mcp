# NIC-side dataplane on the Netronome Agilio CX (Vision) — what works, and how

**Result (2026-08-28, measured):** a per-path packet counter written in eBPF runs **on the Agilio
itself** — JIT-compiled to NFP microcode, with its map resident on the card. 160 UDP packets sent
across 16 source ports produced exactly 10 per bin in the on-card map. This closes HURDLES **H7**:
the XDP route is real, not theoretical.

## What is possible, and what is not

| | status |
|---|---|
| eBPF/XDP **hardware offload** (`xdpoffload`) | **works** — proven end to end |
| eBPF/XDP driver mode (host CPU) | works |
| **Native P4 on the NFP** (`nfp4build` → custom `.nffw`) | **not possible here** — the Netronome/Corigine SDK is proprietary and is not on any lab machine; only the stock `nic`, `flower` and `bpf` firmware apps ship with the kernel |
| P4 → eBPF → offload (`p4c` eBPF/XDP backend) | possible but unbuilt: `p4c` is not packaged for Ubuntu (source build), and it accepts a subset of P4 (no TNA registers/externs) |

## Procedure

Firmware app (the card ships pinned to the plain NIC app):

```bash
FW=/lib/firmware/netronome/pci-0000:af:00.0.nffw.zst   # device-specific override, wins over defaults
sudo cp -P $FW ${FW}.orig                              # once
sudo rdma link delete rxe0                             # rxe holds the netdev
sudo rmmod nfp
sudo ln -sfn bpf/nic_AMDA0097-0001_8x10.nffw.zst $FW   # ebpf app for THIS card (AMDA0097, 8x10)
sudo modprobe nfp                                      # ethtool -i now reports "bpf-2.0.6.124 ebpf"
sudo /home/decps/lab_link_setup.sh                     # restore addresses + rxe0 (the reload flaps the link)
```

Build and load (the card needs spare TX rings for XDP):

```bash
clang -O2 -g -Wall -target bpf -I/usr/include/x86_64-linux-gnu -c xdp_count.c -o xdp_count.o
sudo ethtool -L enp175s0np1s0 combined 4        # else: "nfp: Insufficient number of TX rings w/ XDP enabled"
sudo ip link set dev enp175s0np1s0 xdpoffload obj xdp_count.o sec xdp
bpftool prog show | grep xdp_count              # -> "offloaded_to enp175s0np1s0"
bpftool map dump id <id>                        # counters read back from the card
sudo ip link set dev enp175s0np1s0 xdpoffload off
```

Revert to the NIC app: point `$FW` back at `nic/nic_AMDA0097-0001_8x10.nffw.zst` (or restore
`${FW}.orig`), `rmmod nfp; modprobe nfp`, then re-run `lab_link_setup.sh`. **The card is currently
left on the `nic` app**, because that is the day-to-day Soft-RoCE testbed; flip it only for XDP work.

## Traps that cost time here (all verified)

1. `clang` needs `-I/usr/include/x86_64-linux-gnu`, else `asm/types.h` is missing.
2. `linux/in.h` must be included for `IPPROTO_UDP`.
3. XDP on NFP needs a TX ring per RX ring: halve `combined` first.
4. **NetworkManager strips runtime `ip addr add` when the link flaps** (a driver reload does this).
   Addresses were added to the NM profiles; `lab_link_setup.sh` re-applies them either way.
5. Soft-RoCE picks its GID from the **primary** address: a stale `10.0.2.10/16` on the direct-link
   port made rxe advertise the wrong GID and the transfer silently moved 0 bytes. Removed.
6. `ib_write_bw -x 1` (explicit GID index) also produced 0 iterations on this pair — **omit it**;
   without it the pair runs at ~515–804 MB/s over 4 QPs on the 10 G link.
7. `pkill -f <name>` from an SSH command matches the SSH command itself and kills the session; use
   `pkill -x`.
