# OIB Converter

Convert [OpenIntuneBaseline](https://github.com/SkipToTheEndpoint/OpenIntuneBaseline) JSON profiles to Apple Configuration Profile (.mobileconfig) format.

## Features

- Converts Microsoft Intune Settings Catalogue JSON to Apple mobileconfig XML
- Uses Microsoft Graph API schema for accurate enumeration resolution
- Batch conversion via YAML mapping file
- Supports Microsoft Defender, Edge, Office, OneDrive, and system profiles
- Handles nested settings (antivirusEngine, cloudService, etc.)
- Converts string booleans to proper XML boolean types

## Quick Start

```bash
# 1. Install uv and just
curl -LsSf https://astral.sh/uv/install.sh | sh
brew install just  # or: cargo install just

# 2. Clone and sync dependencies
git clone https://github.com/Talieisin/oib-converter.git
cd oib-converter
just sync

# 3. Configure Azure credentials
cp .env.example .env
# Edit .env with your credentials (see below)

# 4. Fetch Graph API schema
just fetch-schema

# 5. Convert all profiles
just convert
```

## Azure Credential Setup

The Graph API schema fetcher requires Azure AD credentials with read access to Intune configuration settings.

### Option 1: Create a Dedicated App Registration (Recommended)

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
   - Add: `DeviceManagementManagedDevices.Read.All`
6. Click **Grant admin consent for [your org]**

### Option 2: Use Existing Credentials

If you already have an Azure service principal with Intune access, use those credentials.

### Configure Credentials

```bash
cp .env.example .env
# Edit .env with your values
```

Or set environment variables:

```bash
export CLIENT_ID=your-app-id
export CLIENT_SECRET=your-secret
export TENANT_ID=your-tenant-id
```

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

## Known Issues

### Inconsistent Setting IDs in Microsoft Graph API

Some macOS `settingDefinitionId` values in the Intune Settings Catalogue are missing the `com.apple.` prefix (e.g., `loginwindow_loginwindow` instead of `com.apple.loginwindow_loginwindow`). This is a bug in the Microsoft Graph API, not this tool.

We work around this by:
1. Including additional keywords in our schema filter (`loginwindow`, `screensaver`)
2. Mapping malformed setting prefixes to their correct PayloadType in the converter

If you encounter "Unknown setting" warnings for settings that should exist, please open an issue.

Bug reported to Microsoft Intune support (December 2025).

## Development

This project uses [uv](https://docs.astral.sh/uv/) for dependency management and [just](https://github.com/casey/just) for task running.

```bash
# List available commands
just

# Install dependencies
just sync

# Available commands
just fetch-schema    # Fetch Graph API schema (requires Azure credentials)
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
