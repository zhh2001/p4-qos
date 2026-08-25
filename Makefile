P4C ?= p4c-bm2-ss
PYTHON ?= python3

override BUILD_DIR := build
P4_SOURCE := p4/qos.p4
P4_JSON := $(BUILD_DIR)/qos.json
P4INFO := $(BUILD_DIR)/qos.p4info.txtpb

.PHONY: build test clean

build: $(P4_JSON) $(P4INFO)

$(P4_JSON) $(P4INFO) &: $(P4_SOURCE) Makefile
	mkdir -p $(BUILD_DIR)
	$(P4C) --std p4-16 --Werror \
		--p4runtime-files $(P4INFO) --p4runtime-format text \
		-o $(P4_JSON) $(P4_SOURCE)

test: build
	$(PYTHON) -m unittest discover -s tests -p 'test_*.py' -v

clean:
	$(RM) -r -- build
	find . -path './.git' -prune -o -type d \
		\( -name '__pycache__' -o -name '.pytest_cache' \
		-o -name '.mypy_cache' -o -name '.ruff_cache' \) \
		-prune -exec $(RM) -r -- {} +
	find . -path './.git' -prune -o -type f \
		\( -name '*.pyc' -o -name '*.pyo' \) \
		-exec $(RM) -- {} +
