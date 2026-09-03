# Makefile for MCP — Measurement Control Plane
#
# Prerequisites:
#   - p4c (P4 compiler with p4c-bm2-ss backend)
#   - simple_switch_grpc (BMv2 with gRPC support)
#   - Mininet
#   - Python 3.8+ with: scapy, grpcio, protobuf, p4runtime, matplotlib
#
# Quick start:
#   make build          # compile P4 program
#   make run-topo       # start Mininet with BMv2 (terminal 1)
#   make run-mcp        # start MCP controller     (terminal 2)
#   make run-traffic    # generate test traffic     (terminal 3)
#
# Evaluation:
#   make dry-run        # test MCP logic without switches
#   make eval-all       # run all (scenario x selector) combinations
#   make eval-baselines # compare all baselines on single_ddos
#   make plot           # generate comparison plots

P4C = p4c-bm2-ss
P4SRC = p4src/mcp_switch.p4
P4JSON = p4src/build/mcp_switch.json
P4INFO = p4src/build/mcp_switch.p4info.txt

.PHONY: build run-topo run-mcp run-traffic dry-run clean help
.PHONY: eval-all eval-baselines eval-scenario plot check
.PHONY: download-dataset eval-dataset list-datasets

help:
	@echo ""
	@echo "MCP — Measurement Control Plane Implementation"
	@echo ""
	@echo "Setup:"
	@echo "  make build            Compile P4 program for BMv2"
	@echo "  make check            Verify prerequisites are installed"
	@echo ""
	@echo "Running:"
	@echo "  make run-topo         Start Mininet with BMv2 switches (sudo)"
	@echo "  make run-mcp          Start MCP controller (new terminal)"
	@echo "  make run-traffic      Generate test traffic (from Mininet)"
	@echo ""
	@echo "Evaluation:"
	@echo "  make dry-run          Test MCP algorithm without switches"
	@echo "  make eval-baselines   Compare all selectors (dry-run)"
	@echo "  make eval-all         Full evaluation matrix (dry-run)"
	@echo "  make plot             Generate comparison plots"
	@echo ""
	@echo "Selectors: mcp, fixed_polling, adaptive_polling,"
	@echo "  placement_only, centrality_sampling, sketch_only, fixed_mcp"
	@echo ""
	@echo "Scenarios: steady, flash, single_ddos, multi_attack,"
	@echo "  resource_pressure"
	@echo ""
	@echo "Dataset (CICIDS2017):"
	@echo "  make download-dataset Download CICIDS2017 CSV files"
	@echo "  make list-datasets    List available dataset files"
	@echo "  make eval-dataset     Evaluate on CICIDS2017 scenarios (dry-run)"
	@echo ""
	@echo "  Dataset scenarios: cicids_wednesday, cicids_friday_ddos,"
	@echo "  cicids_friday_portscan"
	@echo ""
	@echo "Cleanup:"
	@echo "  make clean            Remove build artifacts and results"
	@echo ""

# --- CHECK PREREQUISITES ---
check:
	@echo "Checking prerequisites..."
	@which $(P4C) > /dev/null 2>&1 || echo "  WARNING: $(P4C) not found"
	@which simple_switch_grpc > /dev/null 2>&1 || echo "  WARNING: simple_switch_grpc not found"
	@python3 -c "import scapy" 2>/dev/null || echo "  WARNING: scapy not installed"
	@python3 -c "import grpc" 2>/dev/null || echo "  WARNING: grpcio not installed"
	@python3 -c "import p4.v1" 2>/dev/null || echo "  WARNING: p4runtime not installed"
	@python3 -c "import matplotlib" 2>/dev/null || echo "  WARNING: matplotlib not installed"
	@echo "Done."

# --- BUILD ---
build: $(P4JSON)

$(P4JSON): $(P4SRC)
	@mkdir -p p4src/build
	$(P4C) --p4v 16 \
		--p4runtime-files $(P4INFO) \
		-o $(P4JSON) \
		$(P4SRC)
	@echo ""
	@echo "Build successful:"
	@echo "  JSON:   $(P4JSON)"
	@echo "  P4Info: $(P4INFO)"

# --- RUN TOPOLOGY ---
run-topo: $(P4JSON)
	sudo python3 topology/topo.py --p4json $(P4JSON)

# --- RUN MCP CONTROLLER ---
run-mcp:
	python3 controller/mcp_controller.py --verbose --epochs 60

# Specify selector:
run-mcp-%:
	python3 controller/mcp_controller.py --verbose --epochs 60 --selector $*

# --- DRY RUN ---
dry-run:
	python3 controller/mcp_controller.py --dry-run --verbose --epochs 30

dry-run-%:
	python3 controller/mcp_controller.py --dry-run --verbose --epochs 30 --selector $*

# --- TRAFFIC ---
run-traffic:
	@echo "Run from the Mininet CLI (after 'make run-topo'):"
	@echo ""
	@echo "  Scenario: single_ddos (recommended)"
	@echo "    h1 python3 traffic/traffic_gen.py --scenario single_ddos &"
	@echo ""
	@echo "  Scenario: multi_attack"
	@echo "    h1 python3 traffic/traffic_gen.py --scenario multi_attack &"
	@echo ""
	@echo "  Scenario: steady (baseline)"
	@echo "    h1 python3 traffic/traffic_gen.py --scenario steady &"

# --- EVALUATION ---

# Compare all selectors on single_ddos scenario (dry-run)
eval-baselines:
	python3 run_experiment.py --scenario single_ddos --selector all --dry-run

# Run one scenario with one selector
eval-scenario:
	python3 run_experiment.py --scenario $(SCENARIO) --selector $(SELECTOR) --dry-run --verbose

# Full evaluation matrix (all scenarios x all selectors)
eval-all:
	python3 run_experiment.py --all --dry-run

# --- PLOTTING ---
plot:
	python3 plot_results.py

# --- DATASET ---

# Download CICIDS2017 CSVs (recommended subset: wednesday, friday_ddos, friday_afternoon)
download-dataset:
	python3 datasets/dataset_manager.py --download cicids2017

# List available dataset files
list-datasets:
	python3 datasets/dataset_manager.py --list

# Evaluate all selectors on CICIDS2017 dataset scenarios (dry-run)
eval-dataset:
	python3 run_experiment.py --scenario cicids_wednesday --selector all --dry-run
	python3 run_experiment.py --scenario cicids_friday_ddos --selector all --dry-run
	python3 run_experiment.py --scenario cicids_friday_portscan --selector all --dry-run

# Evaluate one CICIDS2017 scenario
eval-dataset-%:
	python3 run_experiment.py --scenario cicids_$* --selector all --dry-run

# --- CLEAN ---
clean:
	rm -rf p4src/build
	rm -rf results
	rm -f *.pyc
	rm -rf __pycache__ controller/__pycache__ topology/__pycache__ traffic/__pycache__ datasets/__pycache__
	@echo "Cleaned. (Dataset CSVs in datasets/data/ preserved — use 'make clean-dataset' to remove)"

clean-dataset:
	rm -rf datasets/data
	@echo "Dataset files removed."
