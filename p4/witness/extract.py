#!/usr/bin/env python3
"""Extract the M2 compile-gate numbers from one bf-p4c output tree.

Every number printed names the exact file and field it came from.
"""
import json, os, re, sys, collections

prog = sys.argv[1]
# argv[2], when given, is the directory holding <prog>.tofino -- used for LOCAL
# (laptop SDE 9.13.1) builds.  With no argv[2] the default is the switch's build
# directory, so the COMPILE-GATE.md reproduction recipe is unchanged.
build_dir = sys.argv[2] if len(sys.argv) > 2 else "/home/decps/mcp_m2_gate"
root = os.path.join(build_dir, "%s.tofino" % prog)
res = json.load(open(os.path.join(root, "pipe/logs/resources.json")))["resources"]
ctx = json.load(open(os.path.join(root, "pipe/context.json")))
tsum = open(os.path.join(root, "pipe/logs/table_summary.log")).read()
phvs = open(os.path.join(root, "pipe/logs/phv_allocation_summary_0.log")).read()

out = {"program": prog,
       "compiler": json.load(open(os.path.join(root, "pipe/logs/resources.json")))["compiler_version"]}

# ---- table_summary.log : last allocation block --------------------------------
blk = tsum.rsplit("Table allocation done", 1)[-1]
def grab(pat):
    m = re.search(pat, blk)
    return int(m.group(1)) if m else None
out["table_summary.log"] = {
    "stages_total": grab(r"Number of stages in table allocation:\s+(\d+)"),
    "stages_ingress": grab(r"Number of stages for ingress table allocation:\s+(\d+)"),
    "stages_egress": grab(r"Number of stages for egress table allocation:\s+(\d+)"),
    "critical_path_len": grab(r"Critical path length through the table dependency graph:\s+(\d+)"),
    "tables_allocated": grab(r"Number of tables allocated:\s+(\d+)"),
}

# ---- context.json : placed stages per direction (independent cross-check) ------
# (filled in below, after the gress map is built)

# ---- resources.json : mau_stages, attributed to a gress by table-name prefix ---
def gress(name):
    if name.startswith("Ingress.") or name.startswith("ingress"):
        return "ingress"
    if name.startswith("Egress.") or name.startswith("egress"):
        return "egress"
    return "anon"   # bf-p4c names anonymous (gateway/cond) tables tbl_<prog><LINE>

# anonymous tables: resolve their gress from context.json
NAME2GRESS = {t["name"]: t.get("direction", "?") for t in ctx["tables"]}
def gress2(name):
    if name in NAME2GRESS:
        return NAME2GRESS[name]
    for suf in ("-gateway", "$salu", "$action"):
        if name.endswith(suf) and name[:-len(suf)] in NAME2GRESS:
            return NAME2GRESS[name[:-len(suf)]]
    g = gress(name)
    return g if g != "anon" else "UNRESOLVED:" + name

sram = collections.Counter(); tcam = collections.Counter()
salu = collections.Counter(); stat = collections.Counter()
ltid = collections.Counter(); mapram = collections.Counter()
stages_with = collections.defaultdict(set)
salu_names = collections.defaultdict(list); stat_names = collections.defaultdict(list)
for st in res["mau"]["mau_stages"]:
    sn = st["stage_number"]
    for e in st["logical_tables"]["ids"]:
        g = gress2(e["table_name"]); ltid[g] += 1; stages_with[g].add(sn)
    for e in st["rams"]["srams"]:
        gs = {gress2(u["used_by"]) for u in e["usages"]}
        for g in gs:
            sram[g] += 1.0 / len(gs)
    for e in st["map_rams"]["maprams"]:
        gs = {gress2(u["used_by"]) for u in e["usages"]}
        for g in gs:
            mapram[g] += 1.0 / len(gs)
    for e in st["tcams"]["tcams"]:
        gs = {gress2(u["used_by"]) for u in e["usages"]}
        for g in gs:
            tcam[g] += 1.0 / len(gs)
    for e in st["meter_alus"]["meters"]:
        for u in e["usages"]:
            g = gress2(u["used_by"]); salu[g] += 1
            salu_names[g].append("st%d:%s(%s)" % (sn, u["used_by"], u.get("used_for")))
    for e in st["statistic_alus"]["stats"]:
        for u in e["usages"]:
            g = gress2(u["used_by"]); stat[g] += 1
            stat_names[g].append("st%d:%s(%s)" % (sn, u["used_by"], u.get("used_for")))

out["stages_from_resources.json_logical_tables"] = {
    g: {"n_stages": len(v), "stages": sorted(v)} for g, v in sorted(stages_with.items())}
out["resources.json"] = {
    "nStages_available": res["mau"]["nStages"],
    "mau_stages_populated": len(res["mau"]["mau_stages"]),
    "sram_blocks": {k: round(v, 2) for k, v in sram.items()},
    "sram_blocks_total": round(sum(sram.values()), 2),
    "map_rams": {k: round(v, 2) for k, v in mapram.items()},
    "tcam_blocks": {k: round(v, 2) for k, v in tcam.items()},
    "tcam_blocks_total": round(sum(tcam.values()), 2),
    "meter_alus_salu": dict(salu), "meter_alu_detail": dict(salu_names),
    "statistic_alus": dict(stat), "statistic_alu_detail": dict(stat_names),
    "logical_table_ids": dict(ltid),
    "logical_table_ids_total": sum(ltid.values()),
}

# ---- phv_allocation_summary_0.log : overall + per-group ------------------------
def row(label):
    m = re.search(r"\|\s*%s\s*\|([^\n]*)\|" % re.escape(label), phvs)
    if not m:
        return None
    cells = [c.strip() for c in m.group(1).split("|")]
    return cells
out["phv_allocation_summary_0.log"] = {
    "Overall PHV Usage": row("Overall PHV Usage"),
    "Usage for 8b": row("Usage for 8b"),
    "Usage for 16b": row("Usage for 16b"),
    "Usage for 32b": row("Usage for 32b"),
    "columns": ["Containers Used", "Bits Used", "Bits Used on Ingress",
                "Bits Used on Egress", "Bits Allocated", "Bits Alloc Ingress",
                "Bits Alloc Egress", "Available Bits"],
}
groups = {}
for g in ["B0-15","B16-31","H0-15","H16-31","H32-47","W0-15","W16-31"]:
    r = row(g)
    if r:
        groups[g] = r[:2]
out["phv_allocation_summary_0.log"]["mau_groups_containers_bits"] = groups
m = re.search(r"\|\s*Total\s*\|\s*\|([^\n]*)\|", phvs)
if m:
    out["phv_allocation_summary_0.log"]["tagalong_Total"] = [c.strip() for c in m.group(1).split("|")]

# ---- parser / deparser --------------------------------------------------------
out["resources.json_parser_deparser"] = {
    "parser": {k: (v if not isinstance(v, (list, dict)) else "…") for k, v in res["parser"].items()},
}
print(json.dumps(out, indent=1))
