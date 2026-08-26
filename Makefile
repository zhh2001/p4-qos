P4C ?= p4c-bm2-ss
PYTHON ?= python3
GO ?= go
SUDO ?= sudo

override BUILD_DIR := build
P4_SOURCE := p4/qos.p4
P4_JSON := $(BUILD_DIR)/qos.json
P4INFO := $(BUILD_DIR)/qos.p4info.txtpb
CONTROLLER := $(BUILD_DIR)/qos-controller
CONTROLLER_SOURCES := $(wildcard controller/*.go)

.PHONY: build test test-unit test-integration run clean

build: $(P4_JSON) $(P4INFO) $(CONTROLLER)

$(P4_JSON) $(P4INFO) &: $(P4_SOURCE) Makefile
	mkdir -p $(BUILD_DIR)
	$(P4C) --std p4-16 --Werror \
		--p4runtime-files $(P4INFO) --p4runtime-format text \
		-o $(P4_JSON) $(P4_SOURCE)

$(CONTROLLER): $(CONTROLLER_SOURCES) go.mod go.sum
	mkdir -p $(BUILD_DIR)
	$(GO) build -o $(CONTROLLER) ./controller

test: test-unit test-integration

test-unit: build
	$(GO) test ./...
	$(GO) vet ./...
	$(PYTHON) -m unittest discover -s tests -p 'test_structure.py' -v
	$(PYTHON) -m py_compile mininet/qos_topology.py tests/test_structure.py \
		tests/test_forwarding.py

test-integration: build
	$(SUDO) env PYTHONDONTWRITEBYTECODE=1 $(PYTHON) \
		-m unittest discover -s tests \
		-p 'test_forwarding.py' -v

run: build
	$(SUDO) env PYTHONDONTWRITEBYTECODE=1 $(PYTHON) \
		mininet/qos_topology.py \
		--controller $(CONTROLLER) --p4info $(P4INFO) \
		--device-config $(P4_JSON)

clean:
	$(RM) -r -- build
	find . -path './.git' -prune -o -type d \
		\( -name '__pycache__' -o -name '.pytest_cache' \
		-o -name '.mypy_cache' -o -name '.ruff_cache' \) \
		-prune -exec $(RM) -r -- {} +
	find . -path './.git' -prune -o -type f \
		\( -name '*.pyc' -o -name '*.pyo' \) \
		-exec $(RM) -- {} +
