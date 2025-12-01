# OIB Converter - Command Runner
# Install just: https://github.com/casey/just#installation

# List available commands
default:
    @just --list

# Install dependencies with uv
sync:
    uv sync

# Fetch Graph API schema (requires Azure credentials in .env)
fetch-schema:
    uv run ./scripts/fetch-graph-schema.sh

# Fetch OIB profiles from GitHub
fetch-profiles:
    uv run ./scripts/fetch-oib-profiles.sh

# Convert all profiles using mapping.yaml
convert:
    uv run python -m oib_converter.converter --batch --verbose

# Run linters (ruff, shellcheck)
lint:
    uv run ruff check src/
    shellcheck scripts/*.sh

# Remove generated files and caches
clean:
    rm -rf cache/graph-schema.json
    rm -rf cache/oib-macos/
    rm -rf output/*
    rm -rf .pytest_cache/
    rm -rf src/*.egg-info/
    find . -type d -name __pycache__ -exec rm -rf {} +
