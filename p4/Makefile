# Makefile — offline bf-p4c build for mcp_fabric.p4 (docs/P4-DESIGN-SPACE.md §9.2).
#
# LOCAL SDE is 9.13.1; the switch runs 9.13.2.  Iterate here for speed, then
# RE-COMPILE ON THE SWITCH before any hardware run and diff the resource report.
# Any change in stage count, logical-table-ID occupancy or PHV group saturation
# between the two is a blocker to investigate, not a rounding difference.
#
#   make            # compile, print the real bf-p4c exit status
#   make report     # compile + stage / SRAM / TCAM / LTID summary
#   make phv        # PHV allocation summary (watch the 8-bit MAU group, N12)
#   make resources  # stages actually used, read from context.json
#   make clean

SDE         ?= /home/philip/bf-sde-9.13.1
SDE_INSTALL ?= $(SDE)/install
BFP4C       ?= $(SDE_INSTALL)/bin/bf-p4c

PROG    := mcp_fabric
SRC     := $(PROG).p4
OUTDIR  := $(PROG).tofino
SCHEMA  := $(PROG).bfrt.json
LOGDIR  := $(OUTDIR)/pipe/logs

.PHONY: all report phv resources clean

# --verbose 2 is REQUIRED: without it pipe/logs/ is created but left EMPTY, so
# mau.resources.log / phv_allocation_summary_0.log never appear.  Measured on
# 9.13.1 this session.
all:
	@$(BFP4C) --target tofino --arch tna --verbose 2 \
	    -o $(OUTDIR) --bf-rt-schema $(SCHEMA) \
	    $(SRC) ; st=$$? ; echo "bf-p4c exit status: $$st" ; exit $$st

report: all
	@echo "=== $(LOGDIR)/mau.resources.log (per-stage summary) ==="
	@grep -A200 'Stage Resource Summary' $(LOGDIR)/mau.resources.log 2>/dev/null \
	  || sed -n '1,80p' $(LOGDIR)/mau.resources.log 2>/dev/null \
	  || echo "no mau.resources.log"

phv: all
	@for f in $(LOGDIR)/phv_allocation_summary_*.log ; do \
	    echo "=== $$f ===" ; sed -n '1,60p' $$f ; done

resources: all
	@python3 -c 'import json,collections; c=json.load(open("$(OUTDIR)/pipe/context.json")); \
	s=collections.defaultdict(set); \
	[s[t.get("direction")].add(t["stage"]) for t in c["tables"] if "stage" in t]; \
	[print(d, "stages used:", len(v), sorted(v)) for d,v in sorted(s.items())]'

clean:
	rm -rf $(OUTDIR) $(SCHEMA)
