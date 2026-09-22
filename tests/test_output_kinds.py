import json
from pathlib import Path

import pytest

from oib_converter.converter import (
    BatchConverter,
    GraphSchemaLoader,
    MobileconfigGenerator,
    OutputCompatibilityError,
    SettingConverter,
)


def write_schema(path: Path, settings: dict) -> GraphSchemaLoader:
    path.write_text(
        json.dumps({"generated_at": "2099-01-01T00:00:00Z", "settings": settings})
    )
    return GraphSchemaLoader(path)



@pytest.fixture
def schema(tmp_path):
    settings = {}
    for key in ["softwareupdate_softwareupdate", "softwareupdate_automaticactions"]:
        settings[key] = {"applicability": {"technologies": "appleRemoteManagement"}}
    for action in ["download", "installosupdates", "installsecurityupdate"]:
        key = f"softwareupdate_automaticactions_{action}"
        settings[key] = {
            "applicability": {"technologies": "appleRemoteManagement"},
            "options": [{"itemId": f"{key}_{index}",
                         "optionValue": {"value": value},
                         "dependentOn": [{"parentSettingId": "softwareupdate_automaticactions"}]}
                        for index, value in [(1, "AlwaysOn"), (2, "AlwaysOff")]],
        }
    return write_schema(tmp_path / "schema.json", settings)

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


def test_software_update_migration_is_provider_ready(schema) -> None:
    artifact = BatchConverter._migrate_macos27_software_update(
        software_update_source(), schema
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


def test_software_update_migration_preserves_disabled_actions(schema) -> None:
    source = software_update_source(enabled=False)
    for setting in source["settings"]:
        setting_id = setting["settingDefinitionId"]
        if setting_id.endswith("automaticcheckenabled") or setting_id.endswith(
            "automaticallyinstallappupdates"
        ):
            setting["choiceSettingValue"]["value"] = f"{setting_id}_true"

    encoded = json.dumps(
        BatchConverter._migrate_macos27_software_update(source, schema), sort_keys=True
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


def test_software_update_migration_fails_when_source_semantics_drift(schema) -> None:
    with pytest.raises(OutputCompatibilityError, match="review the semantic migration"):
        BatchConverter._migrate_macos27_software_update({"settings": []}, schema)


def test_software_update_migration_fails_on_unclassified_source_control(schema) -> None:
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
        BatchConverter._migrate_macos27_software_update(source, schema)


@pytest.mark.parametrize("field,value,message", [
    ("configdatainstall", False, "source values differ"),
    ("automaticcheckenabled", False, "disabling automatic update discovery"),
    ("automaticallyinstallappupdates", False, "global App Store"),
    ("restrict-software-update-require-admin-to-install", True, "admin requirement"),
])
def test_rejects_unrepresentable_source(schema, field, value, message):
    source = software_update_source()
    for setting in source["settings"]:
        if setting["settingDefinitionId"] == f"com.apple.softwareupdate_{field}":
            setting["choiceSettingValue"]["value"] = (
                f"com.apple.softwareupdate_{field}_{str(value).lower()}"
            )
    with pytest.raises(OutputCompatibilityError, match=message):
        BatchConverter._migrate_macos27_software_update(source, schema)


def test_choice_ids_are_resolved_by_meaning(schema):
    definition = schema.get_setting_definition("softwareupdate_automaticactions_download")
    definition["options"][0]["itemId"] = "download_new_always_on"
    definition["options"][1]["itemId"] = "download_new_always_off"
    encoded = json.dumps(
        BatchConverter._migrate_macos27_software_update(software_update_source(), schema)
    )
    assert "download_new_always_on" in encoded
    assert "download_new_always_off" not in encoded
    definition["options"][0]["optionValue"]["value"] = "Unexpected"
    with pytest.raises(OutputCompatibilityError, match="unique AlwaysOn"):
        BatchConverter._migrate_macos27_software_update(software_update_source(), schema)


@pytest.mark.parametrize("options", [
    {"output_kind": "settings_catalog_json", "migration": "macos27_software_update"},
    {"output_kind": "mobileconfig", "migration": "macos27_software_update"},
    {"output_kind": "unknown"},
    {},
])
def test_batch_output_contract(tmp_path, schema, options):
    import yaml
    source = tmp_path / "source"
    source.mkdir()
    (source / "updates.json").write_text(json.dumps(software_update_source()))
    mapping = tmp_path / "mapping.yaml"
    mapping.write_text(yaml.safe_dump({"profiles": [{
        "oib_name": "updates", "output_path": "updates.settings.json", **options,
    }]}))
    batch = BatchConverter(mapping, tmp_path / "out", source_path=source)
    converter = SettingConverter(schema)
    generator = MobileconfigGenerator(converter, schema)
    expected = options.get("output_kind") == "settings_catalog_json"
    assert batch.convert_all(converter, generator) == ((1, 0) if expected else (0, 1))
    output = tmp_path / "out/updates.settings.json"
    assert output.exists() == expected
    if expected:
        before = output.read_bytes()
        assert json.loads(before)["technologies"] == "appleRemoteManagement"
        assert batch.convert_all(converter, generator) == (1, 0)
        assert output.read_bytes() == before
