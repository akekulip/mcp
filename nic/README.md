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
