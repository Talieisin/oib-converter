.PHONY: help setup fetch-schema fetch-profiles convert lint test clean

VENV := .venv
PYTHON := $(VENV)/bin/python
PIP := $(VENV)/bin/pip

help:
	@echo "OIB Converter - Available commands:"
	@echo ""
	@echo "  make setup          Create virtual environment and install dependencies"
	@echo "  make fetch-schema   Fetch Graph API schema (requires Azure credentials)"
	@echo "  make fetch-profiles Fetch OIB profiles from GitHub"
	@echo "  make convert        Convert all profiles using mapping.yaml"
	@echo "  make lint           Run linters (ruff, shellcheck)"
	@echo "  make test           Run tests"
	@echo "  make clean          Remove generated files and caches"
	@echo ""

setup:
	python3 -m venv $(VENV)
	$(PIP) install --upgrade pip
	$(PIP) install -e ".[dev]"
	@echo ""
	@echo "Setup complete. Activate with: source $(VENV)/bin/activate"
	@echo "Next: Copy .env.example to .env and add credentials, then run 'make fetch-schema'"

fetch-schema:
	./scripts/fetch-graph-schema.sh

fetch-profiles:
	./scripts/fetch-oib-profiles.sh

convert:
	$(PYTHON) -m oib_converter.converter --batch --verbose

lint:
	$(VENV)/bin/ruff check src/
	shellcheck scripts/*.sh

test:
	$(VENV)/bin/pytest tests/ -v

clean:
	rm -rf cache/graph-schema.json
	rm -rf cache/oib-macos/
	rm -rf output/*
	rm -rf .pytest_cache/
	rm -rf src/*.egg-info/
	find . -type d -name __pycache__ -exec rm -rf {} +
