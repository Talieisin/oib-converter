# OIB Converter

Convert [OpenIntuneBaseline](https://github.com/SkipToTheEndpoint/OpenIntuneBaseline) JSON profiles to Apple Configuration Profile (.mobileconfig) format.

## Features

- Converts Microsoft Intune Settings Catalog JSON to Apple mobileconfig XML
- Uses Microsoft Graph API schema for accurate enumeration resolution
- Batch conversion via YAML mapping file
- Supports Microsoft Defender, Edge, Office, OneDrive, and system profiles
- Handles nested settings (antivirusEngine, cloudService, etc.)
- Converts string booleans to proper XML boolean types
- Emits reviewed Settings Catalog/DDM JSON through explicit semantic migrations
- Rejects DDM-only settings from mobileconfig output

Mappings use `output_kind: settings_catalog_json` plus a named `migration` for
DDM artifacts. Generated JSON contains stable policy metadata and raw setting
instances; callers encode each instance for the Terraform provider. A raw JSON
copy is deliberately unsupported because changing deployment technology can
also change setting semantics.

## Quick Start

```bash
# 1. Install the toolchain (Homebrew-owned; mise supplies Python)
curl -LsSf https://astral.sh/uv/install.sh | sh
brew install just jq mise direnv shellcheck  # shellcheck is needed by `just lint`

# 2. Clone
git clone https://github.com/Talieisin/oib-converter.git
cd oib-converter

# 3. Trust the project tooling (one-time)
mise trust    # accepts mise.toml — pins Python 3.12
direnv allow  # accepts .envrc — loads your Azure credentials from your store

# 4. Supply Azure credentials (see "Azure Credential Setup" below)
just env-check  # reports which of the three names are still unset

# 5. Sync dependencies, fetch the schema, convert
just sync
just fetch-schema
just convert
```

A fresh clone needs no file copying: `.envrc` reads your credentials from
`~/.config/env/oib-converter.env`, and `just fetch-schema` regenerates
`cache/graph-schema.json` (~37 MB, git-ignored, required by every conversion).
Run `just sync` before `just fetch-schema` — the fetcher uses `.venv`.

## Azure Credential Setup

The Graph API schema fetcher requires Azure AD credentials with read access to Intune configuration settings.

A caller that already holds a suitable Graph token (for example CI signed in
through OIDC) can pass it instead; see
[Pre-acquired token](#pre-acquired-token-no-client-secret).

### Option 1: Create a Dedicated App Registration

1. Go to [Azure Portal > App Registrations](https://portal.azure.com/#blade/Microsoft_AAD_RegisteredApps/ApplicationsListBlade)
2. Click **New registration**
   - Name: `OIB Converter Schema Reader`
   - Supported account types: Single tenant
   - Click **Register**
3. Note the **Application (client) ID** and **Directory (tenant) ID**
4. Go to **Certificates & secrets** > **Client secrets** > **New client secret**
   - Description: `Schema reader secret`
   - Expiry: 24 months
   - Copy the **Value** (shown only once)
5. Go to **API permissions** > **Add a permission** > **Microsoft Graph** > **Application permissions**
   - Add: `DeviceManagementConfiguration.Read.All`
6. Click **Grant admin consent for [your org]**

`DeviceManagementConfiguration.Read.All` is the only permission the fetcher
needs. It calls one endpoint, `GET /beta/deviceManagement/configurationSettings`
(with paging and retries), and Microsoft documents
`DeviceManagementConfiguration.Read.All` as the least-privileged application
permission for it. Earlier versions of this README also asked for
`DeviceManagementManagedDevices.Read.All`; nothing here uses it.

### Option 2: An existing service principal

Do not reuse an Intune admin or Terraform service principal. The fetcher only
needs read access to one endpoint, and an admin service principal's secret
would then sit in your local store with far more power than the fetch needs.
If you use a service principal locally, make it a dedicated one with only
`DeviceManagementConfiguration.Read.All`, as in Option 1.

### Configure Credentials

With a client secret (Options 1 and 2), three variables are required:
`CLIENT_ID`, `TENANT_ID` and `CLIENT_SECRET`. A pre-acquired token needs none of them.
`.env.example` is the key-only schema — it never contains values.

**This repository is public.** None of the three belongs in a tracked file,
including the tenant and client IDs.

**Preferred — encrypted store (survives a fresh clone, nothing in the repo):**

```bash
chezmoi edit ~/.config/env/oib-converter.env  # age-encrypted in your dotfiles
direnv allow                                  # one-time, per checkout
just env-check                                # confirms all three are set
```

`.envrc` loads that file automatically whenever you `cd` into the project.

**Alternative — export in your shell:**

```bash
export CLIENT_ID=your-app-id
export CLIENT_SECRET=your-secret
export TENANT_ID=your-tenant-id
```

**Fallback — tree-local `.env`** (git-ignored, but does not survive a fresh
clone, so prefer one of the above):

```bash
cp .env.example .env
# Edit .env with your values
```

### Pre-acquired token (no client secret)

If `GRAPH_ACCESS_TOKEN` is exported, `fetch-graph-schema.sh` uses it as the
Graph bearer token and skips `.env`, `CLIENT_ID` / `CLIENT_SECRET` /
`TENANT_ID` and MSAL entirely, so the fetcher itself needs no client secret.

It is for callers that already hold a Graph token with
`DeviceManagementConfiguration.Read.All`. The typical case is CI that signs
in a dedicated app registration through workload identity federation (GitHub
OIDC to Entra, then `az account get-access-token --resource-type ms-graph`):

```bash
(
  GRAPH_ACCESS_TOKEN=$(az account get-access-token --resource-type ms-graph --query accessToken -o tsv) &&
  export GRAPH_ACCESS_TOKEN &&
  ./scripts/fetch-graph-schema.sh
)
```

The subshell keeps the token out of the calling shell, and the `&&` chain
stops if `az` fails. Never type a literal token on the command line, where
it would land in your shell history.

A personal `az login` does **not** work here. That token belongs to the
Azure CLI's own app, which is not granted any Intune (`DeviceManagement*`)
scope, so Graph answers 403 and the fetcher stops with
`Error fetching data: 403 Client Error: Forbidden for url: https://graph.microsoft.com/beta/deviceManagement/configurationSettings`.

- It is read from the exported environment only. A `GRAPH_ACCESS_TOKEN` line
  in `.env` is ignored, as is anything `.env` sets under the script's own
  internal names.
- The script reads and unsets the variable before it starts any other
  process, never prints the value, and rejects anything that is not a bare
  token (three base64url segments, no `Bearer ` prefix) without echoing it.
- If `CLIENT_SECRET` is also exported, the token wins, a warning says
  `CLIENT_SECRET` was ignored, and the script unsets `CLIENT_SECRET` so no
  child process inherits it.

## Usage

### Batch Conversion (Recommended)

Convert all profiles defined in `mapping.yaml`:

```bash
just convert
# Or directly:
uv run oib-converter --batch --verbose
```

Output is written to `output/` directory:
```
output/
├── defender/
│   ├── antivirus-config.mobileconfig
│   └── mde-config.mobileconfig
├── system/
│   ├── device-restrictions.mobileconfig
│   ├── filevault.mobileconfig
│   └── ...
├── edge/
│   └── ...
└── ...
```

The batch is intentionally multi-format. The current mapping emits 17
mobileconfig files and one reviewed Settings Catalog/DDM JSON artifact for
software-update settings. Conversion is not assumed to be lossless across
deployment technologies: the named migration verifies every legacy source
control, validates generated setting and choice IDs against the fetched Graph
schema, and fails on unsupported source changes. It reconstructs the three OS/security
update controls; it is not a generic Graph JSON passthrough or raw Apple declaration
exporter. `source_coverage` records controls that are superseded or need separate
management. In particular, the global App Store auto-update preference has no
replacement here: manage app updates independently and review that coverage before
retiring the legacy payload.

Use `output_kind: settings_catalog_json`, `migration: macos27_software_update`,
and a `.settings.json` output path together. The default `mobileconfig` kind
requires a `.mobileconfig` path and rejects migration options. Enum choices are
resolved from their Apple values and parent in the cached Graph schema.

### Single File Conversion

```bash
uv run oib-converter --profile path/to/oib-profile.json --output profile.mobileconfig
```

### CLI Options

```
--profile PATH      Path to OIB JSON profile file
--output PATH       Output path for mobileconfig file
--batch             Run batch conversion using mapping file
--mapping PATH      Path to mapping YAML (default: mapping.yaml)
--output-dir PATH   Output directory for batch (default: output/)
--source-path PATH  Local directory to read OIB JSON profiles from in
                    batch mode instead of downloading from GitHub.
                    Accepts either (a) the root of an OpenIntuneBaseline
                    checkout (the converter auto-detects
                    MACOS/NativeImport) or (b) a directory containing
                    the "<oib_name>.json" files directly. Useful for
                    pinning to a specific upstream commit or for
                    offline / air-gapped builds.
--schema PATH       Path to Graph schema (default: cache/graph-schema.json)
--organisation NAME Organisation name (default: Talieisin)
--payload-type TYPE Override PayloadType detection
--verbose           Enable debug logging
```

## Mapping File

Edit `mapping.yaml` to customise which profiles to convert:

```yaml
profiles:
  - oib_name: "MacOS - OIB - Defender Antivirus - D - Antivirus Configuration - v1.0"
    output_path: "defender/antivirus-config.mobileconfig"
    enabled: true
    notes: "Defender antivirus settings"

config:
  organisation: "Talieisin"
  default_scope: "System"
  removal_disallowed: true
  default_output_dir: "/path/to/output"  # Optional: override default output directory
```

## Schema Refresh

The Graph API schema should be refreshed quarterly or when:
- New OIB baseline versions are released
- Conversion errors indicate missing settings

```bash
just fetch-schema
```

## Supported Profiles

| Category | Profiles |
|----------|----------|
| **Microsoft Defender** | Antivirus Config, MDE Config |
| **System Security** | Device Restrictions, Accounts/Login, FileVault, Gatekeeper, Software Updates |
| **Microsoft Edge** | Security, Extensions, Password Management, Profiles/Sign-in/Sync, Updates |
| **Microsoft 365** | Office Config, MAU (AutoUpdate), OneDrive (KFM, Service Access) |
| **Authentication** | Platform SSO |

## Validation

After conversion, validate the output with:

```bash
# macOS built-in plist syntax validator
plutil -lint output/**/*.mobileconfig

# For deeper validation (payload structure, required keys, value types)
# https://github.com/Talieisin/mobileconfig-validator
mobileconfig-validator output/**/*.mobileconfig
```

## Limitations

- **FileVault Recovery Key Escrow**: Requires Intune-injected certificates, cannot be converted to standalone mobileconfig
- **Platform SSO**: Full functionality requires Intune deployment
- **Global App Store automatic updates**: Apple's DDM software-update settings
  declaration has no replacement for the legacy
  `AutomaticallyInstallAppUpdates` preference. Managed apps use their own
  delivery/update channel; DDM-managed apps can use per-app
  `com.apple.configuration.app.managed` `UpdateBehavior`. Unmanaged App Store
  apps need an explicit operational decision when the legacy SoftwareUpdate
  payload is retired.

## Known Issues

### Inconsistent Setting IDs in Microsoft Graph API

Some macOS `settingDefinitionId` values in the Intune Settings Catalog are missing the `com.apple.` prefix (e.g., `loginwindow_loginwindow` instead of `com.apple.loginwindow_loginwindow`). This is a bug in the Microsoft Graph API, not this tool.

We work around this by:
1. Including additional keywords in our schema filter (`loginwindow`, `screensaver`)
2. Mapping malformed setting prefixes to their correct PayloadType in the converter

If you encounter "Unknown setting" warnings for settings that should exist, please open an issue.

Bug reported to Microsoft Intune support (December 2025).

## Development

This project uses [uv](https://docs.astral.sh/uv/) for dependency management and [just](https://github.com/casey/just) for task running.
[mise](https://mise.jdx.dev/) pins the Python runtime (`mise.toml`, currently
3.12 — the highest version CI exercises); `uv`, `just`, `jq` and `shellcheck`
are Homebrew-owned and deliberately absent from `mise.toml`.
[direnv](https://direnv.net/) loads credentials via `.envrc` — secrets only, no
PATH or layout directives, so the two layers stay disjoint.

Note that `just clean` deletes `cache/graph-schema.json`; rebuild it with
`just fetch-schema`, which needs working credentials.

```bash
# List available commands
just

# Install dependencies
just sync

# Available commands
just env-check       # Report which Azure credential names are unset (never values)
just fetch-schema    # Fetch Graph API schema (Azure credentials or GRAPH_ACCESS_TOKEN)
just fetch-profiles  # Fetch OIB profiles from GitHub
just convert         # Convert all profiles using mapping.yaml
just lint            # Run linters (ruff, shellcheck)
just clean           # Remove generated files and caches
```

## Contributing

For issues and contributions, please use the GitHub issue tracker.

## Licence

MIT

---

**Maintained By**: Talieisin IT Team
