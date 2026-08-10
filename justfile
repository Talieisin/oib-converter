# OIB Converter - Command Runner
# Install just: https://github.com/casey/just#installation

# List available commands
default:
    @just --list

# Install dependencies with uv
sync:
    uv sync

# Report which Azure credential variables are set (names only, never values)
env-check:
    #!/usr/bin/env bash
    set -euo pipefail
    missing=""
    [ -n "${CLIENT_ID:-}" ]     || missing="$missing CLIENT_ID"
    [ -n "${CLIENT_SECRET:-}" ] || missing="$missing CLIENT_SECRET"
    [ -n "${TENANT_ID:-}" ]     || missing="$missing TENANT_ID"
    if [ -z "$missing" ]; then
        echo "env-check: OK — CLIENT_ID, CLIENT_SECRET and TENANT_ID are all set."
        exit 0
    fi
    echo "env-check: the following required variables are unset:"
    for name in $missing; do
        echo "  - $name"
    done
    echo
    echo "Supply them from your encrypted store:"
    echo "  chezmoi edit ~/.config/env/oib-converter.env   # then: direnv allow"
    echo "See .env.example for the key schema."
    if [ -f .env ]; then
        echo
        echo "Note: a tree-local .env exists and fetch-schema still reads it as a"
        echo "fallback, so that command may work even though this check fails."
    fi
    exit 1

# Fetch Graph API schema (requires Azure credentials — see `just env-check`)
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
