#!/usr/bin/env bash

############################################################################################
##
## Microsoft Graph API Schema Fetcher
##
## Downloads setting definitions from Microsoft Graph API and caches them locally.
## This cache is used by the OIB converter to resolve enumeration values accurately.
##
## Credentials are loaded from .env file or environment variables.
##
## Usage:
##   1. With .env file:
##      cp .env.example .env
##      # Edit .env with your credentials
##      ./scripts/fetch-graph-schema.sh
##
##   2. With environment variables:
##      CLIENT_ID=xxx CLIENT_SECRET=xxx TENANT_ID=xxx ./scripts/fetch-graph-schema.sh
##
## Output: cache/graph-schema.json
##
## Frequency: Run quarterly or when adopting new OIB baseline versions
##
############################################################################################

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
OUTPUT_FILE="${REPO_ROOT}/cache/graph-schema.json"
ENV_FILE="${REPO_ROOT}/.env"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check for required tools
command -v python3 >/dev/null 2>&1 || { log_error "python3 is required but not installed"; exit 1; }
command -v jq >/dev/null 2>&1 || { log_error "jq is required but not installed. Install with: brew install jq"; exit 1; }

# Create cache directory
mkdir -p "${REPO_ROOT}/cache"

# Load credentials from .env file if it exists
if [[ -f "$ENV_FILE" ]]; then
    log_info "Loading credentials from .env file..."
    set -a
    # shellcheck disable=SC1090
    source "$ENV_FILE"
    set +a
fi

# Validate credentials
if [[ -z "${CLIENT_ID:-}" ]] || [[ -z "${CLIENT_SECRET:-}" ]] || [[ -z "${TENANT_ID:-}" ]]; then
    log_error "Missing required credentials"
    log_error ""
    log_error "Option 1: Create .env file from .env.example:"
    log_error "  cp .env.example .env"
    log_error "  # Edit .env with your Azure App Registration credentials"
    log_error ""
    log_error "Option 2: Set environment variables:"
    log_error "  export CLIENT_ID=your-app-id"
    log_error "  export CLIENT_SECRET=your-secret"
    log_error "  export TENANT_ID=your-tenant-id"
    log_error ""
    log_error "See README.md for creating an Azure App Registration"
    exit 1
fi

log_info "Credentials loaded successfully"
log_info "Client ID: $CLIENT_ID"
log_info "Tenant ID: $TENANT_ID"

# Check for Python virtual environment
VENV_PYTHON="${REPO_ROOT}/.venv/bin/python3"
if [[ ! -f "$VENV_PYTHON" ]]; then
    log_error "Python virtual environment not found"
    log_error "Create it with: just sync"
    log_error "Or manually: python3 -m venv .venv && .venv/bin/pip install pyyaml requests msal"
    exit 1
fi

# Check for msal
if ! "$VENV_PYTHON" -c "import msal" 2>/dev/null; then
    log_error "MSAL not installed. Run: just sync"
    log_error "Or manually: .venv/bin/pip install msal"
    exit 1
fi

# Authenticate with Microsoft Graph API
log_info "Authenticating with Microsoft Graph API..."

# Pass credentials via environment variables to avoid shell injection
TOKEN_RESPONSE=$(CLIENT_ID="$CLIENT_ID" CLIENT_SECRET="$CLIENT_SECRET" TENANT_ID="$TENANT_ID" \
    "$VENV_PYTHON" <<'EOF'
import os
import sys
import json
try:
    import msal
except ImportError:
    print(json.dumps({"error": "msal not installed"}))
    sys.exit(1)

client_id = os.environ.get("CLIENT_ID", "")
client_secret = os.environ.get("CLIENT_SECRET", "")
tenant_id = os.environ.get("TENANT_ID", "")
authority = f"https://login.microsoftonline.com/{tenant_id}"
scopes = ["https://graph.microsoft.com/.default"]

try:
    app = msal.ConfidentialClientApplication(
        client_id,
        authority=authority,
        client_credential=client_secret
    )

    result = app.acquire_token_for_client(scopes=scopes)
    print(json.dumps(result))
except Exception as e:
    print(json.dumps({"error": str(e)}))
    sys.exit(1)
EOF
)

# Check for authentication errors
if echo "$TOKEN_RESPONSE" | jq -e '.error' >/dev/null 2>&1; then
    ERROR_MSG=$(echo "$TOKEN_RESPONSE" | jq -r '.error_description // .error')
    log_error "Authentication failed: $ERROR_MSG"
    exit 1
fi

ACCESS_TOKEN=$(echo "$TOKEN_RESPONSE" | jq -r '.access_token')

if [[ -z "$ACCESS_TOKEN" ]] || [[ "$ACCESS_TOKEN" == "null" ]]; then
    log_error "Failed to obtain access token"
    log_error "Response: $TOKEN_RESPONSE"
    exit 1
fi

log_info "Authentication successful"

# Fetch setting definitions from Graph API
log_info "Fetching setting definitions from Microsoft Graph API..."
log_info "This may take 2-3 minutes for ~2,100 settings..."

GRAPH_URL="https://graph.microsoft.com/beta/deviceManagement/configurationSettings"

# Fetch with pagination support
GENERATED_AT=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

# Pass access token and metadata via environment variables to avoid shell injection
if ! ACCESS_TOKEN="$ACCESS_TOKEN" GRAPH_URL="$GRAPH_URL" GENERATED_AT="$GENERATED_AT" \
    "$VENV_PYTHON" > "$OUTPUT_FILE" <<'EOF'
import os
import sys
import json
import requests

access_token = os.environ.get("ACCESS_TOKEN", "")
url = os.environ.get("GRAPH_URL", "")
generated_at = os.environ.get("GENERATED_AT", "")
headers = {
    "Authorization": f"Bearer {access_token}",
    "Accept": "application/json"
}

all_settings = []
page_count = 0

while url:
    page_count += 1
    print(f"Fetching page {page_count}...", file=sys.stderr)

    try:
        response = requests.get(url, headers=headers, timeout=60)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        print(f"Error fetching data: {e}", file=sys.stderr)
        sys.exit(1)

    data = response.json()
    settings = data.get("value", [])
    all_settings.extend(settings)

    # Check for next page
    url = data.get("@odata.nextLink")

    print(f"  Retrieved {len(settings)} settings (total: {len(all_settings)})", file=sys.stderr)

# Filter to macOS-relevant settings (Apple native + Microsoft apps for macOS)
# Include: apple, mac, microsoft (wdav/defender, edge, office, onedrive, teams)
# Also include: loginwindow, screensaver (some settings lack com.apple. prefix)
def is_macos_relevant(setting_id):
    sid = setting_id.lower()
    return any(kw in sid for kw in [
        "apple", "mac",  # Apple native settings
        "microsoft", "wdav", "defender",  # Microsoft Defender
        "edge", "office", "onedrive", "teams",  # Microsoft apps
        "loginwindow", "screensaver",  # Settings sometimes missing com.apple. prefix
    ])

macos_settings = [s for s in all_settings if is_macos_relevant(s.get("id", ""))]

print(f"\nTotal settings: {len(all_settings)}", file=sys.stderr)
print(f"macOS-relevant settings: {len(macos_settings)}", file=sys.stderr)

# Create schema structure
schema = {
    "version": "1.0",
    "generated_at": generated_at,
    "total_settings": len(macos_settings),
    "settings": {s["id"]: s for s in macos_settings}
}

print(json.dumps(schema, indent=2))
EOF
then
    log_error "Failed to fetch setting definitions"
    exit 1
fi

# Verify output
SETTING_COUNT=$(jq -r '.total_settings' "$OUTPUT_FILE" 2>/dev/null || echo "0")

if [[ "$SETTING_COUNT" -eq 0 ]]; then
    log_error "No settings retrieved. Output file may be invalid."
    exit 1
fi

log_info "Successfully fetched $SETTING_COUNT macOS setting definitions"
log_info "Schema saved to: $OUTPUT_FILE"
log_info "File size: $(du -h "$OUTPUT_FILE" | cut -f1)"

# Display sample settings
log_info ""
log_info "Sample settings retrieved:"
jq -r '.settings | keys | .[:5] | .[]' "$OUTPUT_FILE" | while read -r key; do
    echo "  - $key"
done

log_info ""
log_info "Schema cache is ready for use with the OIB converter"
log_info "Refresh this cache quarterly or when updating OIB baseline versions"
