#!/usr/bin/env bash

############################################################################################
##
## Microsoft Graph API Schema Fetcher
##
## Downloads setting definitions from Microsoft Graph API and caches them locally.
## This cache is used by the OIB converter to resolve enumeration values accurately.
##
## Credentials are read from the environment, with a tree-local .env fallback.
##
## Usage:
##   1. Preferred — encrypted store + direnv (nothing lands in the repo):
##      chezmoi edit ~/.config/env/oib-converter.env
##      direnv allow          # .envrc loads the store on cd
##      ./scripts/fetch-graph-schema.sh
##
##   2. With environment variables:
##      CLIENT_ID=xxx CLIENT_SECRET=xxx TENANT_ID=xxx ./scripts/fetch-graph-schema.sh
##
##   3. Fallback — tree-local .env file (git-ignored):
##      cp .env.example .env
##      # Edit .env with your credentials
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

# Colours for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Colour

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

# Mask an identifier for logging: keep the leading 8 characters (a GUID's first
# block, enough to tell tenants and app registrations apart at a glance) and
# elide the rest. This repo is public and these values live in the encrypted
# store, so a full identifier should never reach stdout or a CI log.
mask_id() {
    local value="$1"
    if [[ ${#value} -le 8 ]]; then
        printf '%s' '********'
    else
        printf '%s...' "${value:0:8}"
    fi
}

# Redact GUID-shaped substrings from arbitrary text. Entra error descriptions
# routinely echo the client or tenant ID back (e.g. AADSTS700016), which would
# otherwise defeat mask_id.
redact_guids() {
    sed -E 's/[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}/<redacted-guid>/g'
}

# Check for required tools
command -v python3 >/dev/null 2>&1 || { log_error "python3 is required but not installed"; exit 1; }
command -v jq >/dev/null 2>&1 || { log_error "jq is required but not installed. Install with: brew install jq"; exit 1; }

# Create cache directory
mkdir -p "${REPO_ROOT}/cache"

# Load credentials from a tree-local .env if one exists.
#
# .env is strictly a FALLBACK: anything already exported (by direnv from
# ~/.config/env/oib-converter.env, or by hand) wins. Sourcing alone would do the
# opposite and let a stale tree-local file silently override the intended
# credentials, so pre-existing values are captured first and restored after.
if [[ -f "$ENV_FILE" ]]; then
    log_info "Loading credentials from .env file (exported environment takes precedence)..."
    exported_client_id="${CLIENT_ID:-}"
    exported_client_secret="${CLIENT_SECRET:-}"
    exported_tenant_id="${TENANT_ID:-}"

    set -a
    # shellcheck disable=SC1090
    source "$ENV_FILE"
    set +a

    # Restore whatever the environment already provided. Plain `if` blocks, not
    # `[[ ... ]] && x=y`, so a false test cannot trip `set -e`.
    if [[ -n "$exported_client_id" ]]; then
        CLIENT_ID="$exported_client_id"
    fi
    if [[ -n "$exported_client_secret" ]]; then
        CLIENT_SECRET="$exported_client_secret"
    fi
    if [[ -n "$exported_tenant_id" ]]; then
        TENANT_ID="$exported_tenant_id"
    fi
    unset exported_client_id exported_client_secret exported_tenant_id
fi

# Validate credentials
if [[ -z "${CLIENT_ID:-}" ]] || [[ -z "${CLIENT_SECRET:-}" ]] || [[ -z "${TENANT_ID:-}" ]]; then
    log_error "Missing required credentials"
    log_error ""
    log_error "Run 'just env-check' to see exactly which names are unset."
    log_error ""
    log_error "Option 1 (preferred): encrypted store, loaded by .envrc"
    log_error "  chezmoi edit ~/.config/env/oib-converter.env"
    log_error "  direnv allow"
    log_error ""
    log_error "Option 2: Set environment variables:"
    log_error "  export CLIENT_ID=your-app-id"
    log_error "  export CLIENT_SECRET=your-secret"
    log_error "  export TENANT_ID=your-tenant-id"
    log_error ""
    log_error "Option 3 (fallback): Create .env file from .env.example:"
    log_error "  cp .env.example .env"
    log_error "  # Edit .env with your Azure App Registration credentials"
    log_error ""
    log_error "See README.md for creating an Azure App Registration"
    exit 1
fi

log_info "Credentials loaded successfully"
log_info "Client ID: $(mask_id "$CLIENT_ID")"
log_info "Tenant ID: $(mask_id "$TENANT_ID")"

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
    ERROR_MSG=$(echo "$TOKEN_RESPONSE" | jq -r '.error_description // .error' | redact_guids)
    log_error "Authentication failed: $ERROR_MSG"
    exit 1
fi

ACCESS_TOKEN=$(echo "$TOKEN_RESPONSE" | jq -r '.access_token')

if [[ -z "$ACCESS_TOKEN" ]] || [[ "$ACCESS_TOKEN" == "null" ]]; then
    log_error "Failed to obtain access token"
    # Strip any token material before echoing the response, then redact GUIDs.
    # If it will not parse as JSON it is not a token response, so say nothing
    # about its contents rather than dumping an unknown blob.
    if SAFE_RESPONSE=$(printf '%s' "$TOKEN_RESPONSE" | jq -c 'del(.access_token, .id_token, .refresh_token)' 2>/dev/null); then
        log_error "Response: $(printf '%s' "$SAFE_RESPONSE" | redact_guids)"
    else
        log_error "Response was not valid JSON; omitted to avoid logging credential material."
    fi
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
