# Regenerate every figure of the manuscript from the committed sweep files.
# Run from anywhere: `make -C paper/ton/figures`. Requires matplotlib >= 3.5 and numpy.
PY ?= python3
SCRIPTS := fig_system.py fig_scaling.py fig_counterpair.py fig_floor.py fig_localization.py fig_silicon.py fig_correlated.py fig_action_rate.py
all:
	@for s in $(SCRIPTS); do echo "== $$s"; $(PY) $(CURDIR)/$$s; done
.PHONY: all
