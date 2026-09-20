import json
from pathlib import Path

import pytest

from oib_converter.converter import (
    BatchConverter,
    GraphSchemaLoader,
    OutputCompatibilityError,
)


def write_schema(path: Path, settings: dict) -> GraphSchemaLoader:
    path.write_text(
        json.dumps({"generated_at": "2099-01-01T00:00:00Z", "settings": settings})
    )
    return GraphSchemaLoader(path)


def test_mobileconfig_rejects_ddm_only_setting(tmp_path: Path) -> None:
    loader = write_schema(
        tmp_path / "schema.json",
        {
            "app_privacy_permissiondefaults": {
                "applicability": {
                    "platform": "iOS,macOS",
                    "technologies": "appleRemoteManagement",
                }
            }
        },
    )

    with pytest.raises(OutputCompatibilityError, match="app_privacy_permissiondefaults"):
        loader.assert_mobileconfig_compatible(
            {"settings": [{"settingDefinitionId": "app_privacy_permissiondefaults"}]}
        )


def test_mobileconfig_accepts_dual_technology_setting(tmp_path: Path) -> None:
    loader = write_schema(
        tmp_path / "schema.json",
        {
            "dual": {
                "applicability": {
                    "platform": "macOS",
                    "technologies": "mdm,appleRemoteManagement",
                }
            }
        },
    )
    loader.assert_mobileconfig_compatible(
        {"settings": [{"settingInstance": {"settingDefinitionId": "dual"}}]}
    )


def software_update_source(enabled: bool = True) -> dict:
    ids = [
        "automaticcheckenabled",
        "automaticdownload",
        "automaticallyinstallappupdates",
        "automaticallyinstallmacosupdates",
        "configdatainstall",
        "criticalupdateinstall",
    ]
    settings = [
        {
            "settingDefinitionId": f"com.apple.softwareupdate_{setting_id}",
            "choiceSettingValue": {
                "value": f"com.apple.softwareupdate_{setting_id}_{str(enabled).lower()}"
            },
        }
        for setting_id in ids
    ]
    settings.append(
        {
            "settingDefinitionId": (
                "com.apple.softwareupdate_"
                "restrict-software-update-require-admin-to-install"
            ),
            "choiceSettingValue": {
                "value": (
                    "com.apple.softwareupdate_"
                    "restrict-software-update-require-admin-to-install_false"
                )
            },
        }
    )
    return {"settings": settings}


def test_software_update_migration_is_provider_ready() -> None:
    artifact = BatchConverter._migrate_macos27_software_update(
        software_update_source()
    )

    assert artifact["technologies"] == "appleRemoteManagement"
    assert artifact["platforms"] == "macOS"
    assert artifact["settings"][0]["settingDefinitionId"] == "softwareupdate_softwareupdate"
    encoded = json.dumps(artifact, sort_keys=True)
    assert "softwareupdate_automaticactions_installosupdates_1" in encoded
    assert "softwareupdate_automaticactions_installsecurityupdate_1" in encoded
    assert "softwareupdate_automaticactions_download_1" in encoded
    assert "softwareupdate_allowstandarduserosupdates" not in encoded
    assert "AutomaticallyInstallAppUpdates" in encoded


def test_software_update_migration_preserves_disabled_actions() -> None:
    source = software_update_source(enabled=False)
    for setting in source["settings"]:
        setting_id = setting["settingDefinitionId"]
        if setting_id.endswith("automaticcheckenabled") or setting_id.endswith(
            "automaticallyinstallappupdates"
        ):
            setting["choiceSettingValue"]["value"] = f"{setting_id}_true"

    encoded = json.dumps(
        BatchConverter._migrate_macos27_software_update(source), sort_keys=True
    )
    assert "softwareupdate_automaticactions_download_2" in encoded
    assert "softwareupdate_automaticactions_installosupdates_2" in encoded
    assert "softwareupdate_automaticactions_installsecurityupdate_2" in encoded


def test_settings_catalog_validation_rejects_invalid_choice(tmp_path: Path) -> None:
    setting_id = "softwareupdate_automaticactions_download"
    loader = write_schema(
        tmp_path / "schema.json",
        {
            setting_id: {
                "applicability": {
                    "platform": "macOS",
                    "technologies": "appleRemoteManagement",
                },
                "options": [{"itemId": f"{setting_id}_1"}],
            }
        },
    )

    with pytest.raises(OutputCompatibilityError, match="invalid choice"):
        loader.assert_settings_catalog_compatible(
            {
                "settings": [
                    {
                        "settingDefinitionId": setting_id,
                        "choiceSettingValue": {"value": f"{setting_id}_true"},
                    }
                ]
            }
        )


def test_software_update_migration_fails_when_source_semantics_drift() -> None:
    with pytest.raises(OutputCompatibilityError, match="review the semantic migration"):
        BatchConverter._migrate_macos27_software_update({"settings": []})


def test_software_update_migration_fails_on_unclassified_source_control() -> None:
    source = software_update_source()
    source["settings"].append(
        {
            "settingDefinitionId": (
                "com.apple.softwareupdate_allowprereleaseinstallation"
            ),
            "choiceSettingValue": {
                "value": "com.apple.softwareupdate_allowprereleaseinstallation_false"
            },
        }
    )

    with pytest.raises(OutputCompatibilityError, match="unclassified controls"):
        BatchConverter._migrate_macos27_software_update(source)
