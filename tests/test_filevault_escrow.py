"""Tests for the filevault_escrow Settings Catalog migration.

The fixtures mirror the shape of OIB's NativeImport export of
"MacOS - OIB - Disk Encryption - D - FileVault - v1.0" (Graph read-back
metadata included) and the technologies the Graph schema declares for each
setting: the FileVault2 core settings are MDM-only.
"""

import copy
import json
from pathlib import Path

import pytest
import yaml

from oib_converter.converter import (
    FILEVAULT_ESCROW_SHAPE,
    BatchConverter,
    GraphSchemaLoader,
    MobileconfigGenerator,
    OutputCompatibilityError,
    SettingConverter,
)

GROUP = "#microsoft.graph.deviceManagementConfigurationGroupSettingCollectionInstance"
CHOICE = "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance"
SIMPLE = "#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance"
STRING = "#microsoft.graph.deviceManagementConfigurationStringSettingValue"

LOCATION_TEXT = (
    "You can retrieve the personal recovery key for your macOS device from the "
    "Microsoft Intune app, Company Portal website, or Company Portal apps for "
    "Android and iOS/iPadOS."
)

# Technologies as the cached Graph schema declares them (2026-10-13).
SCHEMA_TECHNOLOGIES = {
    "com.apple.mcx.filevault2_com.apple.mcx.filevault2": "mdm",
    "com.apple.mcx.filevault2_enable": "mdm",
    "com.apple.mcx.filevault2_forceenableinsetupassistant": "mdm",
    "com.apple.mcx.filevault2_recoverykeyrotationinmonths": "mdm,appleRemoteManagement",
    "com.apple.mcx.filevault2_defer": "mdm",
    "com.apple.mcx_com.apple.mcx-fdefilevaultoptions": "mdm,appleRemoteManagement",
    "com.apple.mcx_dontallowfdedisable": "mdm,appleRemoteManagement",
    "com.apple.security.fderecoverykeyescrow_com.apple.security.fderecoverykeyescrow": (
        "mdm,appleRemoteManagement"
    ),
    "com.apple.security.fderecoverykeyescrow_location": "mdm,appleRemoteManagement",
}

SCHEMA_OPTIONS = {
    "com.apple.mcx.filevault2_enable": ["_0", "_1"],
    "com.apple.mcx.filevault2_forceenableinsetupassistant": ["_false", "_true"],
    "com.apple.mcx.filevault2_recoverykeyrotationinmonths": [f"_{n}" for n in range(13)],
    "com.apple.mcx.filevault2_defer": ["_true"],
    "com.apple.mcx_dontallowfdedisable": ["_false", "_true"],
}


@pytest.fixture
def schema(tmp_path: Path) -> GraphSchemaLoader:
    settings = {}
    for setting_id, technologies in SCHEMA_TECHNOLOGIES.items():
        definition = {"applicability": {"platform": "macOS", "technologies": technologies}}
        if setting_id in SCHEMA_OPTIONS:
            definition["options"] = [
                {"itemId": f"{setting_id}{suffix}"} for suffix in SCHEMA_OPTIONS[setting_id]
            ]
        settings[setting_id] = definition
    path = tmp_path / "schema.json"
    path.write_text(json.dumps({"generated_at": "2099-01-01T00:00:00Z", "settings": settings}))
    return GraphSchemaLoader(path)


def choice(setting_id: str, value: str) -> dict:
    return {
        "@odata.type": CHOICE,
        "settingDefinitionId": setting_id,
        "settingInstanceTemplateReference": None,
        "choiceSettingValue": {
            "settingValueTemplateReference": None,
            "value": value,
            "children": [],
        },
    }


def group(index: int, setting_id: str, children: list[dict]) -> dict:
    return {
        "id": str(index),
        "settingInstance": {
            "@odata.type": GROUP,
            "settingDefinitionId": setting_id,
            "settingInstanceTemplateReference": None,
            "groupSettingCollectionValue": [
                {"settingValueTemplateReference": None, "children": children}
            ],
        },
    }


def filevault_source() -> dict:
    """The upstream NativeImport JSON, Graph read-back metadata included."""
    return {
        "@odata.context": (
            "https://graph.microsoft.com/beta/$metadata#deviceManagement/"
            "configurationPolicies/$entity"
        ),
        "createdDateTime": "2024-08-27T14:33:06.4056266Z",
        "description": "",
        "name": "MacOS - OIB - Disk Encryption - D - FileVault - v1.0",
        "platforms": "macOS",
        "roleScopeTagIds": ["0"],
        "settingCount": 3,
        "technologies": "mdm,appleRemoteManagement",
        "id": "3828f80f-4e13-471d-bfda-52446dc1379c",
        "templateReference": {"templateId": "", "templateFamily": "none"},
        "settings": [
            group(0, "com.apple.mcx.filevault2_com.apple.mcx.filevault2", [
                choice("com.apple.mcx.filevault2_enable",
                       "com.apple.mcx.filevault2_enable_0"),
                choice("com.apple.mcx.filevault2_forceenableinsetupassistant",
                       "com.apple.mcx.filevault2_forceenableinsetupassistant_true"),
                choice("com.apple.mcx.filevault2_recoverykeyrotationinmonths",
                       "com.apple.mcx.filevault2_recoverykeyrotationinmonths_6"),
            ]),
            group(1, "com.apple.mcx_com.apple.mcx-fdefilevaultoptions", [
                choice("com.apple.mcx_dontallowfdedisable",
                       "com.apple.mcx_dontallowfdedisable_true"),
            ]),
            group(2, "com.apple.security.fderecoverykeyescrow_"
                     "com.apple.security.fderecoverykeyescrow", [{
                "@odata.type": SIMPLE,
                "settingDefinitionId": "com.apple.security.fderecoverykeyescrow_location",
                "settingInstanceTemplateReference": None,
                "simpleSettingValue": {
                    "@odata.type": STRING,
                    "settingValueTemplateReference": None,
                    "value": LOCATION_TEXT,
                },
            }]),
        ],
    }


def children_of(source: dict, index: int) -> list[dict]:
    return source["settings"][index]["settingInstance"]["groupSettingCollectionValue"][0][
        "children"
    ]


def all_keys(value) -> set[str]:
    if isinstance(value, dict):
        keys = set(value)
        for child in value.values():
            keys |= all_keys(child)
        return keys
    if isinstance(value, list):
        keys: set[str] = set()
        for child in value:
            keys |= all_keys(child)
        return keys
    return set()


def test_migration_keeps_settings_verbatim_without_graph_metadata(schema) -> None:
    source = filevault_source()
    artifact = BatchConverter._migrate_filevault_escrow(source, schema)

    assert artifact["name"] == "MacOS - OIB - Disk Encryption - D - FileVault - v1.0"
    assert artifact["platforms"] == "macOS"
    assert artifact["technologies"] == "mdm,appleRemoteManagement"
    assert [s["settingDefinitionId"] for s in artifact["settings"]] == list(
        FILEVAULT_ESCROW_SHAPE
    )
    keys = all_keys(artifact["settings"])
    assert "settingInstanceTemplateReference" not in keys
    assert "settingValueTemplateReference" not in keys
    assert "id" not in keys
    assert "@odata.context" not in artifact and "id" not in artifact

    # Every instance is the source instance minus the two null references.
    for produced, entry in zip(artifact["settings"], source["settings"], strict=True):
        original = json.dumps(entry["settingInstance"])
        for key in ("settingInstanceTemplateReference", "settingValueTemplateReference"):
            original = original.replace(f'"{key}": null, ', "")
        assert json.loads(original) == produced

    encoded = json.dumps(artifact)
    assert LOCATION_TEXT in encoded
    assert "com.apple.mcx.filevault2_enable_0" in encoded
    assert "com.apple.mcx.filevault2_forceenableinsetupassistant_true" in encoded
    assert "com.apple.mcx.filevault2_recoverykeyrotationinmonths_6" in encoded
    assert "com.apple.mcx_dontallowfdedisable_true" in encoded
    # Defer is recorded as not added, never set.
    assert "com.apple.mcx.filevault2_defer" in artifact["source_coverage"]["not_added"]
    assert "com.apple.mcx.filevault2_defer" not in json.dumps(artifact["settings"])

    # MDM-only settings are valid in an mdm,appleRemoteManagement policy.
    schema.assert_settings_catalog_compatible(artifact)


def test_migration_does_not_modify_its_source(schema) -> None:
    source = filevault_source()
    before = copy.deepcopy(source)
    BatchConverter._migrate_filevault_escrow(source, schema)
    assert source == before


def test_changed_location_text_passes_through(schema) -> None:
    source = filevault_source()
    children_of(source, 2)[0]["simpleSettingValue"]["value"] = "Ask IT."
    artifact = BatchConverter._migrate_filevault_escrow(source, schema)
    assert "Ask IT." in json.dumps(artifact["settings"])


def test_rejects_an_added_setting(schema) -> None:
    source = filevault_source()
    children_of(source, 0).append(
        choice("com.apple.mcx.filevault2_defer", "com.apple.mcx.filevault2_defer_true")
    )
    with pytest.raises(OutputCompatibilityError,
                       match="unclassified com.apple.mcx.filevault2_defer"):
        BatchConverter._migrate_filevault_escrow(source, schema)


def test_rejects_a_removed_setting(schema) -> None:
    source = filevault_source()
    del source["settings"][2]
    with pytest.raises(OutputCompatibilityError, match="missing .*fderecoverykeyescrow"):
        BatchConverter._migrate_filevault_escrow(source, schema)


def test_rejects_a_repeated_setting(schema) -> None:
    source = filevault_source()
    children_of(source, 1).append(copy.deepcopy(children_of(source, 1)[0]))
    with pytest.raises(OutputCompatibilityError,
                       match="repeated com.apple.mcx_dontallowfdedisable"):
        BatchConverter._migrate_filevault_escrow(source, schema)


@pytest.mark.parametrize("index,child,value", [
    (0, 0, "com.apple.mcx.filevault2_enable_1"),
    (0, 1, "com.apple.mcx.filevault2_forceenableinsetupassistant_false"),
    (0, 2, "com.apple.mcx.filevault2_recoverykeyrotationinmonths_12"),
    (1, 0, "com.apple.mcx_dontallowfdedisable_false"),
])
def test_rejects_a_changed_choice(schema, index, child, value) -> None:
    source = filevault_source()
    children_of(source, index)[child]["choiceSettingValue"]["value"] = value
    with pytest.raises(OutputCompatibilityError, match="values or structure changed"):
        BatchConverter._migrate_filevault_escrow(source, schema)


def test_rejects_a_setting_moved_to_another_group(schema) -> None:
    source = filevault_source()
    moved = children_of(source, 0).pop()
    children_of(source, 1).append(moved)
    with pytest.raises(OutputCompatibilityError, match="regrouped"):
        BatchConverter._migrate_filevault_escrow(source, schema)


def test_rejects_the_location_moved_out_of_an_empty_escrow_group(schema) -> None:
    # Review of #59: the location child keeps its own value wherever it sits,
    # so only the group check catches it leaving the escrow group.
    source = filevault_source()
    location = children_of(source, 2).pop()
    children_of(source, 0).append(location)
    with pytest.raises(OutputCompatibilityError, match="regrouped|no escrow location text"):
        BatchConverter._migrate_filevault_escrow(source, schema)


def test_rejects_extra_keys_in_an_instance(schema) -> None:
    source = filevault_source()
    children_of(source, 0)[0]["choiceSettingValue"]["children"].append({"x": 1})
    with pytest.raises(OutputCompatibilityError, match="values or structure changed"):
        BatchConverter._migrate_filevault_escrow(source, schema)


def test_rejects_a_template_reference(schema) -> None:
    source = filevault_source()
    children_of(source, 0)[0]["settingInstanceTemplateReference"] = {
        "settingInstanceTemplateId": "abc"
    }
    with pytest.raises(OutputCompatibilityError, match="settingInstanceTemplateReference"):
        BatchConverter._migrate_filevault_escrow(source, schema)


@pytest.mark.parametrize("technologies", ["mdm", "appleRemoteManagement", ""])
def test_rejects_changed_technologies(schema, technologies) -> None:
    source = filevault_source()
    source["technologies"] = technologies
    with pytest.raises(OutputCompatibilityError, match="technologies changed"):
        BatchConverter._migrate_filevault_escrow(source, schema)


@pytest.mark.parametrize("text", ["", "   ", None])
def test_rejects_empty_location_text(schema, text) -> None:
    source = filevault_source()
    children_of(source, 2)[0]["simpleSettingValue"]["value"] = text
    with pytest.raises(OutputCompatibilityError, match="escrow location"):
        BatchConverter._migrate_filevault_escrow(source, schema)


def test_ddm_only_artifact_still_rejects_mdm_only_setting(schema) -> None:
    artifact = BatchConverter._migrate_filevault_escrow(filevault_source(), schema)
    artifact["technologies"] = "appleRemoteManagement"
    with pytest.raises(OutputCompatibilityError,
                       match="filevault2_enable is not available through DDM"):
        schema.assert_settings_catalog_compatible(artifact)
    del artifact["technologies"]
    with pytest.raises(OutputCompatibilityError, match="not available through DDM"):
        schema.assert_settings_catalog_compatible(artifact)


def test_validation_rejects_a_setting_outside_the_policy_technologies(schema) -> None:
    artifact = BatchConverter._migrate_filevault_escrow(filevault_source(), schema)
    schema.get_setting_definition("com.apple.mcx.filevault2_enable")["applicability"][
        "technologies"
    ] = "linuxMdm"
    with pytest.raises(OutputCompatibilityError, match="not available through any of"):
        schema.assert_settings_catalog_compatible(artifact)


def test_validation_rejects_a_choice_missing_from_the_schema(schema) -> None:
    artifact = BatchConverter._migrate_filevault_escrow(filevault_source(), schema)
    schema.get_setting_definition("com.apple.mcx.filevault2_enable")["options"] = [
        {"itemId": "com.apple.mcx.filevault2_enable_1"}
    ]
    with pytest.raises(OutputCompatibilityError, match="invalid choice"):
        schema.assert_settings_catalog_compatible(artifact)


def run_batch(tmp_path: Path, schema, profile: dict) -> tuple[tuple[int, int], Path]:
    source_dir = tmp_path / "source"
    source_dir.mkdir(exist_ok=True)
    (source_dir / "filevault.json").write_bytes(
        b"\xef\xbb\xbf" + json.dumps(filevault_source()).encode("utf-8")
    )
    mapping = tmp_path / "mapping.yaml"
    mapping.write_text(yaml.safe_dump({"profiles": [{"oib_name": "filevault", **profile}]}))
    out = tmp_path / "out"
    batch = BatchConverter(mapping, out, source_path=source_dir)
    converter = SettingConverter(schema)
    return batch.convert_all(converter, MobileconfigGenerator(converter, schema)), out


def test_batch_writes_the_settings_catalog_artifact(tmp_path, schema) -> None:
    profile = {
        "output_path": "system/filevault.settings.json",
        "output_kind": "settings_catalog_json",
        "migration": "filevault_escrow",
    }
    result, out = run_batch(tmp_path, schema, profile)
    assert result == (1, 0)
    output = out / "system/filevault.settings.json"
    first = output.read_bytes()
    assert json.loads(first)["technologies"] == "mdm,appleRemoteManagement"
    # Deterministic: a second run writes the same bytes.
    assert run_batch(tmp_path, schema, profile)[0] == (1, 0)
    assert output.read_bytes() == first


def test_batch_rejects_filevault_through_the_software_update_migration(tmp_path, schema) -> None:
    result, out = run_batch(tmp_path, schema, {
        "output_path": "system/filevault.settings.json",
        "output_kind": "settings_catalog_json",
        "migration": "macos27_software_update",
    })
    assert result == (0, 1)
    assert not (out / "system/filevault.settings.json").exists()


def test_repository_mapping_routes_filevault_through_the_migration() -> None:
    mapping = yaml.safe_load(
        (Path(__file__).resolve().parent.parent / "mapping.yaml").read_text()
    )
    entries = [
        p for p in mapping["profiles"]
        if p["oib_name"] == "MacOS - OIB - Disk Encryption - D - FileVault - v1.0"
    ]
    assert len(entries) == 1
    assert entries[0]["output_kind"] == "settings_catalog_json"
    assert entries[0]["migration"] == "filevault_escrow"
    assert entries[0]["output_path"] == "system/filevault.settings.json"
    assert entries[0]["enabled"] is True
