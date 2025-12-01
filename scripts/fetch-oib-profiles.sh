#!/usr/bin/env bash
#
# Fetch OpenIntuneBaseline macOS profiles via sparse git clone
#
# Downloads only the MACOS/ directory from the OIB repository to minimize
# disk usage and clone time. Profiles are stored in cache/oib-macos/
#
# Usage:
#   ./scripts/fetch-oib-profiles.sh          # Clone or update
#   ./scripts/fetch-oib-profiles.sh --force  # Force fresh clone
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
OIB_DIR="$REPO_ROOT/cache/oib-macos"
OIB_REPO="https://github.com/SkipToTheEndpoint/OpenIntuneBaseline.git"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Check for --force flag
FORCE=false
if [[ "${1:-}" == "--force" ]]; then
    FORCE=true
fi

# Create cache directory if needed
mkdir -p "$REPO_ROOT/cache"

if [[ -d "$OIB_DIR/.git" ]] && [[ "$FORCE" == "false" ]]; then
    log_info "Updating existing OIB clone..."
    cd "$OIB_DIR"
    git fetch --depth=1 origin main
    git reset --hard origin/main
    log_info "Updated to latest OIB commit"
else
    if [[ -d "$OIB_DIR" ]]; then
        log_warn "Removing existing directory for fresh clone..."
        rm -rf "$OIB_DIR"
    fi

    log_info "Sparse cloning OpenIntuneBaseline (MACOS directory only)..."

    # Initialize sparse checkout
    git clone --filter=blob:none --no-checkout --depth=1 "$OIB_REPO" "$OIB_DIR"
    cd "$OIB_DIR"

    # Configure sparse checkout to only include MACOS directory
    git sparse-checkout init --cone
    git sparse-checkout set MACOS

    # Checkout
    git checkout main

    log_info "Sparse clone complete"
fi

# Show what we got
echo ""
log_info "OIB macOS profiles available at: $OIB_DIR/MACOS/"
echo ""
echo "Contents:"
find "$OIB_DIR/MACOS" -type f -name "*.json" | head -20
JSON_COUNT=$(find "$OIB_DIR/MACOS" -type f -name "*.json" | wc -l | tr -d ' ')
echo ""
log_info "Total JSON files: $JSON_COUNT"
