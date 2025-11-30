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
# 1. Clone and setup
git clone https://github.com/Talieisin/oib-converter.git
cd oib-converter
make setup

# 2. Configure Azure credentials
cp .env.example .env
# Edit .env with your credentials (see below)

# 3. Fetch Graph API schema
make fetch-schema

# 4. Convert all profiles
make convert
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
make convert
# Or directly:
oib-converter --batch --verbose
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
oib-converter --profile path/to/oib-profile.json --output profile.mobileconfig
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
```

## Schema Refresh

The Graph API schema should be refreshed quarterly or when:
- New OIB baseline versions are released
- Conversion errors indicate missing settings

```bash
make fetch-schema
```

## Supported Profiles

| Category | Profiles |
|----------|----------|
| **Microsoft Defender** | Antivirus Config, MDE Config |
| **System Security** | Restrictions, Accounts/Login, FileVault, Gatekeeper |
| **Software Updates** | Update Configuration |
| **Microsoft 365** | Office, Edge (6 profiles), AutoUpdate, OneDrive |
| **Authentication** | Platform SSO |

## Validation

After conversion, validate the output with:

```bash
# macOS built-in validator
plutil -lint output/**/*.mobileconfig

# Or use mobileconfig-validator (separate tool)
pip install mobileconfig-validator
mobileconfig-validator output/**/*.mobileconfig
```

## Limitations

- **FileVault Recovery Key Escrow**: Requires Intune-injected certificates, cannot be converted to standalone mobileconfig
- **Platform SSO**: Full functionality requires Intune deployment
- **Unknown Settings**: Settings not in Graph API schema are skipped with warnings

## Contributing

For issues and contributions, please use the GitHub issue tracker.

## Licence

MIT

---

**Maintained By**: Talieisin IT Team
