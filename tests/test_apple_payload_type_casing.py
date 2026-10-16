"""Apple payload types must come out in Apple's casing.

macOS matches PayloadType case-sensitively. The converter used to emit
com.apple.tcc.configuration-profile-policy, which macOS 27.0.1 installed as a
plain preferences domain, so TCC never applied the OIB Defender and OneDrive
grants.
"""

import json
from pathlib import Path

import pytest

from oib_converter.apple_payload_types import (
    APPLE_PAYLOAD_TYPES,
    canonical_apple_payload_type,
)
from oib_converter.converter import (
    GraphSchemaLoader,
    MobileconfigGenerator,
    OutputCompatibilityError,
    SettingConverter,
)

TCC = "com.apple.TCC.configuration-profile-policy"

# Domains the Graph settings catalogue (schema of 2026-10-13) derives from
# lowercase setting IDs, which the converter emitted mis-cased before this fix.
PREVIOUSLY_MISCASED = {
    "com.apple.assetcache.managed": "com.apple.AssetCache.managed",
    "com.apple.dictionary": "com.apple.Dictionary",
    "com.apple.directoryservice.managed": "com.apple.DirectoryService.managed",
    "com.apple.discrecording": "com.apple.DiscRecording",
    "com.apple.dnssettings.managed": "com.apple.dnsSettings.managed",
    "com.apple.mcx.timemachine": "com.apple.MCX.TimeMachine",
    "com.apple.mcxmenuextras": "com.apple.mcxMenuExtras",
    "com.apple.nsextension": "com.apple.NSExtension",
    "com.apple.profileremovalpassword": "com.apple.profileRemovalPassword",
    "com.apple.security.fderecoverykeyescrow": "com.apple.security.FDERecoveryKeyEscrow",
    "com.apple.systemconfiguration": "com.apple.SystemConfiguration",
    "com.apple.tcc.configuration-profile-policy": TCC,
}

# The hand-kept map this list replaced; every entry must still hold.
FORMER_KNOWN_MAPPINGS = {
    "com.apple.softwareupdate": "com.apple.SoftwareUpdate",
    "com.apple.mcx.filevault2": "com.apple.MCX.FileVault2",
    "com.apple.mcx": "com.apple.MCX",
    "com.apple.extensiblesso": "com.apple.extensiblesso",
    "com.apple.applicationaccess": "com.apple.applicationaccess",
    "com.apple.security.firewall": "com.apple.security.firewall",
    "com.apple.loginwindow": "com.apple.loginwindow",
    "com.apple.screensaver": "com.apple.screensaver",
    "com.apple.systempolicy.control": "com.apple.systempolicy.control",
    "com.apple.eas.account": "com.apple.eas.account",
    "com.apple.configurationprofile.identification": (
        "com.apple.configurationprofile.identification"
    ),
}


def write_schema(path: Path, settings: dict) -> GraphSchemaLoader:
    path.write_text(json.dumps({"generated_at": "2099-01-01T00:00:00Z", "settings": settings}))
    return GraphSchemaLoader(path)


def choice_definition(setting_id: str, key: str, value: str) -> dict:
    return {
        "baseUri": "",
        "offsetUri": key,
        "options": [{"itemId": f"{setting_id}_0", "optionValue": {"value": value}}],
    }


def choice_instance(setting_id: str) -> dict:
    return {
        "settingInstance": {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
            "settingDefinitionId": setting_id,
            "choiceSettingValue": {"value": f"{setting_id}_0"},
        }
    }


def convert(loader: GraphSchemaLoader, setting_ids: list[str]) -> dict:
    generator = MobileconfigGenerator(SettingConverter(loader), loader)
    return generator.convert_json_to_mobileconfig(
        {"name": "Test", "settings": [choice_instance(s) for s in setting_ids]}
    )


def test_tcc_setting_emits_apple_payload_type(tmp_path: Path) -> None:
    setting_id = "com.apple.tcc.configuration-profile-policy_identifier"
    loader = write_schema(
        tmp_path / "schema.json",
        {setting_id: choice_definition(setting_id, "Identifier", "com.microsoft.wdav")},
    )
    profile = convert(loader, [setting_id])
    payload_types = [p["PayloadType"] for p in profile["PayloadContent"]]
    assert payload_types == [TCC]
    assert profile["PayloadContent"][0]["PayloadIdentifier"].startswith(f"{TCC}.")


@pytest.mark.parametrize(("domain", "expected"), sorted(PREVIOUSLY_MISCASED.items()))
def test_previously_miscased_domains_are_canonical(
    tmp_path: Path, domain: str, expected: str
) -> None:
    setting_id = f"{domain}_somekey"
    loader = write_schema(tmp_path / "schema.json", {setting_id: {"baseUri": ""}})
    assert loader.get_payload_type(setting_id) == expected


@pytest.mark.parametrize(("domain", "expected"), sorted(FORMER_KNOWN_MAPPINGS.items()))
def test_former_known_mappings_still_hold(domain: str, expected: str) -> None:
    assert canonical_apple_payload_type(domain) == expected


@pytest.mark.parametrize("payload_type", sorted(APPLE_PAYLOAD_TYPES))
def test_every_apple_type_round_trips_from_lowercase(payload_type: str) -> None:
    assert canonical_apple_payload_type(payload_type.lower()) == payload_type
    assert canonical_apple_payload_type(payload_type) == payload_type


def test_apple_type_list_has_no_case_collisions() -> None:
    lowered = [t.lower() for t in APPLE_PAYLOAD_TYPES]
    assert len(set(lowered)) == len(lowered)


def test_apple_type_list_is_complete_release_v27() -> None:
    # 117 distinct com.apple.* payloadtype values at apple/device-management
    # Release-v27.0 (09f249a). A refresh changes this number deliberately.
    assert len(APPLE_PAYLOAD_TYPES) == 117
    assert all(t.startswith("com.apple.") for t in APPLE_PAYLOAD_TYPES)


@pytest.mark.parametrize(
    "payload_type",
    ["com.apple.TimeMachine", "com.apple.timemachine", "com.microsoft.wdav", "com.example.App"],
)
def test_unlisted_types_pass_through(payload_type: str) -> None:
    assert canonical_apple_payload_type(payload_type) == payload_type


def test_base_uri_payload_types_are_canonicalised(tmp_path: Path) -> None:
    loader = write_schema(
        tmp_path / "schema.json",
        {
            "apple_setting": {
                "baseUri": "PayloadContent/com.apple.tcc.configuration-profile-policy/Services",
            },
            "vendor_setting": {
                "baseUri": "PayloadContent/com.microsoft.wdav/Forced/[0]/"
                "mcx_preference_settings/antivirusEngine",
            },
        },
    )
    assert loader.parse_base_uri("apple_setting") == (TCC, None)
    assert loader.parse_base_uri("vendor_setting") == ("com.microsoft.wdav", "antivirusEngine")


def test_fde_recovery_key_escrow_is_still_skipped(tmp_path: Path) -> None:
    # The skip list was keyed on the lowercase type; now that the type comes
    # out as com.apple.security.FDERecoveryKeyEscrow it must still be skipped.
    escrow = "com.apple.security.fderecoverykeyescrow_location"
    firewall = "com.apple.security.firewall_enablefirewall"
    loader = write_schema(
        tmp_path / "schema.json",
        {
            escrow: choice_definition(escrow, "Location", "IT"),
            firewall: choice_definition(firewall, "EnableFirewall", "true"),
        },
    )
    profile = convert(loader, [escrow, firewall])
    assert [p["PayloadType"] for p in profile["PayloadContent"]] == [
        "com.apple.security.firewall"
    ]


def convert_with_override(tmp_path: Path, custom: str) -> dict:
    firewall = "com.apple.security.firewall_enablefirewall"
    loader = write_schema(
        tmp_path / "schema.json", {firewall: choice_definition(firewall, "EnableFirewall", "true")}
    )
    generator = MobileconfigGenerator(SettingConverter(loader), loader)
    return generator.convert_json_to_mobileconfig(
        {"name": "Test", "settings": [choice_instance(firewall)]}, custom_payload_type=custom
    )


@pytest.mark.parametrize(
    "custom", ["com.apple.security.fderecoverykeyescrow", "com.apple.security.FDERecoveryKeyEscrow"]
)
def test_fde_recovery_key_escrow_override_is_rejected_in_either_casing(
    tmp_path: Path, custom: str
) -> None:
    # Skipping the override's payload would leave only the empty fallback
    # payload, which carries the override as its PayloadType. So no escrow
    # PayloadType may come out at all: the profile fails instead.
    with pytest.raises(OutputCompatibilityError, match="FDERecoveryKeyEscrow") as excinfo:
        profile = convert_with_override(tmp_path, custom)
        emitted = [p["PayloadType"] for p in profile["PayloadContent"]]
        pytest.fail(f"escrow override produced output with PayloadTypes {emitted}")
    assert "cannot be converted" in str(excinfo.value)


@pytest.mark.parametrize(
    ("custom", "expected"),
    [
        ("com.apple.tcc.configuration-profile-policy", TCC),
        (TCC, TCC),
        ("com.microsoft.wdav", "com.microsoft.wdav"),
        ("com.apple.TimeMachine", "com.apple.TimeMachine"),
    ],
)
def test_payload_type_override_is_canonicalised(
    tmp_path: Path, custom: str, expected: str
) -> None:
    profile = convert_with_override(tmp_path, custom)
    assert [p["PayloadType"] for p in profile["PayloadContent"]] == [expected]
