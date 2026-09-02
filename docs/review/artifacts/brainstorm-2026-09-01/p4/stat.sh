#!/bin/bash
P="$1"; D="$(dirname "$0")/${P}.tofino/pipe/logs"
grep -E "Number of stages for (ingress|egress) table allocation|Critical path length|Number of tables allocated" "$D/table_summary.log" | tail -4
python3 - "$D/resources.json" <<'PY'
import json,sys
r=json.load(open(sys.argv[1]))["resources"]["mau"]
s=sum(len(st.get("rams",{}).get("srams",[])) for st in r["mau_stages"])
m=sum(len(st.get("map_rams",{}).get("maprams",[])) for st in r["mau_stages"])
t=sum(len(st.get("tcams",{}).get("tcams",[])) for st in r["mau_stages"])
al=sum(len(st.get("meter_alus",{}).get("meters",[])) for st in r["mau_stages"])
print(f"srams={s} maprams={m} tcams={t} salus={al}")
PY
