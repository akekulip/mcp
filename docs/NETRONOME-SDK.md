# Getting native P4 on the Agilio (nfp4build / nfp4c) — research findings, 2026-08-28

**Question:** can we obtain the Netronome P4 toolchain (`nfp4build`, `nfp4c`) so the Agilio CX in
Vision can run P4 rather than only eBPF/XDP?

**Answer:** it exists, it is not on GitHub or in any public repository, and the vendor's own licence
position is that it ships **to owners of the hardware**. We own the hardware, so the route is a
support request — not a download. Below is everything verified, with what was checked.

## What the toolchain is

`nfp4build` and `nfp4c` are part of the **Agilio P4C SDK** (latest cited: 6.0/6.1), installed at
`/opt/netronome/p4/bin`. The SDK is three pieces: Programmer Studio IDE (Windows), the Run Time
Environment (`rte`, with `rtecli`), and the hosted toolchain. Real tarball names seen in public
build scripts: `nfp-sdk-p4-rte-6.1.0.1-preview-3214.ubuntu.x86_64.tgz`,
`nfp-sdk-6-rte-r540a-2016-02-02-binary.tar.gz`. Typical invocation:

```
nfp4build --nfp4c_p4_version 16 --no-debug-info -p out -o firmware.nffw -l lithium -4 prog.p4
```

(`-l` is the platform: `lithium`/`starfighter1` etc. — our card is AMDA0097-0001, NFP-4000 "beryllium".)

## What is publicly available (checked, live)

| source | status | contains |
|---|---|---|
| `https://deb.netronome.com/apt` (stable main) | **live**, built 2021-05-11 | 8 packages: `nfp-bsp-6000-b0`, `agilio-nfp-driver-dkms`, `agilio-nic-firmware`, `agilio-flower-app-firmware`, `agilio-sriov-firmware`, `virtio-forwarder`, … — **BSP yes, SDK no** |
| `https://rpm.netronome.com/repos/centos/` | listed in the same article | RPM equivalents |
| `help.netronome.com` support portal | **live** | firmware, drivers, hardware guides; the repositories article states the P4C SDK needs specific component versions "included in the SDK tarballs" |
| GitHub `Netronome/`, `Corigine/`, `open-nfpsw/` | live | drivers (`nfp-drv-kmods`), CoreNIC firmware, and P4 **examples** (`p4_int_transit`, `P4-16_INT`, …) — no toolchain |
| `open-nfp.org` (the old academic programme) | **dead — HTTP 503** | was the historical registration route |
| `downloads.netronome.com` | **dead — no DNS/connection** | — |

Public code that *uses* the toolchain (all assume `/opt/netronome`): `ralfkundel/P4STA`,
`acceltcp/AccelTCP`, `RuiCunhaM/template-netronome-p4`, `praveingk/nfpnic`, `Team-P4RROT/P4RROT`,
`open-nfpsw/*`. None redistributes it.

## The licence position, in their words

Netronome stated that third-party constraints prevent releasing the NFP toolchain under a
non-proprietary licence **and prohibit providing the tooling independently of their hardware**.
That is the reason it is not on GitHub, and it is also why *we* are the eligible case: the SDK is
granted to hardware owners on request.

## The route that exists today

Netronome's NFP line is now **Corigine**. Two live entry points:

- Download portal: `https://www.corigine.com/DPUDownload.html` (dynamic; product/OS filters)
- Support: **smartnic-support@corigine.com** — the address Corigine's own driver README gives
- Netronome's legacy portal `help.netronome.com` is still live; `help@netronome.com` was the old
  address for toolchain eligibility requests.

Our hardware, for the request: **Agilio CX, board `AMDA0097-0001` rev 13, serial
`SMCAMDA0097-000117291655`, NFP-4000, PCI `19ee:4000` at `af:00.0`, 2×40G cages running the 8×10G
breakout firmware, host Ubuntu 24.04 / kernel 6.8**. A draft request is in `docs/netronome-sdk-request.txt`.

## Unofficial copies — and why not to use one

A public Docker image (`ssogunle/p4-netronome:latest`, 691 MB, pushed 2018) appears to bundle an
SDK-era environment. Treat this as **unlicensed redistribution**: it is a licence violation to rely
on, its provenance cannot be checked, and it would poison artifact evaluation for a paper. Not used
here, and not recommended.

## Does the project need it?

No. After the panel pivot the contribution is the **link-local in-band invariant on the Tofino**;
the NIC arm is the operational comparator (B11). We have already proven eBPF/XDP **hardware
offload** on this card (`nic/README-xdp.md`: counter JIT-compiled to NFP microcode, map on-card,
160 packets binned exactly). That is sufficient for a NIC-side arm at line rate.

Native P4-on-NFP would buy: writing the NIC arm in the same language as the switch arm, and a
"two P4 targets" claim. Worth requesting in the background — not worth blocking on.
