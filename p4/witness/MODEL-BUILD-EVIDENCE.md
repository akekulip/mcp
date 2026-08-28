# Build evidence for the model-validated variants

So the model result in `p4/ptf/PTF-MODEL.md` can be audited from this repository alone:
every source below is the file `gen_variants.py` emits and this repository commits, and the
sha256 lets that be checked without the external build directory.

Compiled with the LAPTOP SDE 9.13.1 for the software-model run. **The switch's 9.13.2 is the
authority for silicon** and every placement here must be re-measured there before a chip
session — the compile gate already measured a different placement for a different shape on
9.13.2, so these numbers do not carry over by assumption.

Compiler: `p4c 9.13.1 (SHA: e558d01)`

| variant | source sha256 (first 16) | ingress / egress stages | errors | warnings |
|---|---|---|---|---|
| `mcp_fabric_w4.p4` | `9309c5e2ce185310` | 8 / 3 | 0 | 4 |
| `mcp_fabric_w4_arm.p4` | `208f888f6f83080c` | 8 / 3 | 0 | 4 |
| `mcp_fabric_w4_egdrop.p4` | `37b39548542f48bf` | 8 / 3 | 0 | 4 |

"0 errors, 4 warnings" is the honest form — these compile successfully, not warning-free.

The suite in `p4/ptf/test_w4_witness.py` runs against `mcp_fabric_w4_arm`, the variant the
generator emits rather than a hand-edited copy. `mcp_fabric_w4` (no arming) is the cost
floor, and `mcp_fabric_w4_egdrop` carries the egress-side fault injector needed for an
in-pipeline post-TM drop — compiled, not yet exercised.

Verify from a clean checkout:

```
python3 p4/witness/gen_variants.py            # regenerates the sources
sha256sum p4/witness/mcp_fabric_w4*.p4        # must match the table above
```
