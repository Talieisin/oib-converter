#!/usr/bin/env python3

"""
OpenIntuneBaseline to mobileconfig Converter

Converts Microsoft Intune Settings Catalog JSON profiles (from OpenIntuneBaseline)
to Apple Configuration Profile (mobileconfig) format.

REQUIRES: Microsoft Graph API schema cache for accurate conversion.
Run scripts/fetch-graph-schema.sh first to generate the schema cache.

Usage:
    ./oib-to-mobileconfig.py --profile profile.json --output app.mobileconfig
    ./oib-to-mobileconfig.py --batch --mapping mapping.yaml

Requirements:
    pip install pyyaml requests
"""

import argparse
import json
import logging
import plistlib
import sys
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

# Schema older than this triggers a warning
SCHEMA_MAX_AGE_DAYS = 90

try:
    import yaml
except ImportError:
    yaml = None  # Will be checked at runtime

try:
    import requests
except ImportError:
    requests = None  # Will be checked at runtime

# Logger - configured in main() to avoid side effects when used as library
logger = logging.getLogger(__name__)


def _check_dependencies():
    """Check that required dependencies are installed. Called from main()."""
    if yaml is None:
        print("Error: PyYAML not installed. Run: pip install pyyaml")
        sys.exit(1)
    if requests is None:
        print("Error: requests not installed. Run: pip install requests")
        sys.exit(1)


def parse_bool(value: Any) -> Optional[bool]:
    """
    Parse a boolean value from various representations.

    Graph API often stores booleans as strings ("true"/"false").
    Returns None if the value cannot be parsed as boolean.
    """
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        if value.lower() in ('true', '1', 'yes'):
            return True
        if value.lower() in ('false', '0', 'no'):
            return False
    if isinstance(value, int):
        return bool(value)
    return None


class SchemaError(Exception):
    """Raised when schema is missing or incomplete"""
    pass


class GraphSchemaLoader:
    """Loads and manages Graph API setting definitions schema - REQUIRED for conversion"""

    def __init__(self, schema_path: Path):
        self.schema_path = schema_path
        self.schema = None
        self.settings_map: dict[str, Any] = {}
        self.missing_settings: set[str] = set()

        self._load_schema()

    def _load_schema(self):
        """Load schema from JSON file - raises SchemaError if unavailable"""
        if not self.schema_path.exists():
            raise SchemaError(
                f"\n"
                f"{'=' * 70}\n"
                f"SCHEMA NOT FOUND\n"
                f"{'=' * 70}\n"
                f"\n"
                f"The Graph API schema is required for accurate conversion.\n"
                f"Expected location: {self.schema_path}\n"
                f"\n"
                f"To fetch the schema:\n"
                f"\n"
                f"  1. Configure Azure credentials:\n"
                f"     cp .env.example .env\n"
                f"     # Edit .env with CLIENT_ID, CLIENT_SECRET, TENANT_ID\n"
                f"\n"
                f"  2. Run the schema fetcher:\n"
                f"     just fetch-schema\n"
                f"\n"
                f"See README.md for Azure App Registration setup instructions.\n"
                f"{'=' * 70}\n"
            )

        try:
            with open(self.schema_path) as f:
                self.schema = json.load(f)
                self.settings_map = self.schema.get('settings', {})

            if not self.settings_map:
                raise SchemaError(
                    f"Schema file is empty or invalid: {self.schema_path}\n"
                    f"Re-run: just fetch-schema to regenerate"
                )

            # Check schema age
            self._check_schema_age()

            logger.info(f"Loaded {len(self.settings_map)} setting definitions from schema")

        except json.JSONDecodeError as e:
            raise SchemaError(f"Invalid JSON in schema file: {e}") from e

    def _check_schema_age(self):
        """Warn if schema is older than SCHEMA_MAX_AGE_DAYS"""
        generated_at = self.schema.get('generated_at')
        if not generated_at:
            logger.warning("Schema has no generation timestamp - consider refreshing")
            return

        try:
            # Parse ISO format timestamp (e.g., "2024-01-15T10:30:00Z")
            schema_date = datetime.fromisoformat(generated_at.replace('Z', '+00:00'))
            age_days = (datetime.now(timezone.utc) - schema_date).days

            if age_days > SCHEMA_MAX_AGE_DAYS:
                logger.warning(
                    f"Schema is {age_days} days old (generated {generated_at}). "
                    f"Consider running 'just fetch-schema' to refresh."
                )
            else:
                logger.debug(f"Schema age: {age_days} days (generated {generated_at})")
        except (ValueError, TypeError) as e:
            logger.debug(f"Could not parse schema timestamp: {e}")

    def get_setting_definition(self, setting_id: str) -> Optional[dict[str, Any]]:
        """Get setting definition by ID, tracking missing ones"""
        definition = self.settings_map.get(setting_id)
        if definition is None:
            self.missing_settings.add(setting_id)
        return definition

    def resolve_plist_key(self, setting_id: str) -> Optional[str]:
        """Extract Apple plist key from setting definition"""
        definition = self.get_setting_definition(setting_id)
        if not definition:
            return None

        # Primary: Use offsetUri from Graph API (most accurate)
        offset_uri = definition.get('offsetUri', '')
        if offset_uri:
            # offsetUri is like "antivirusEngine/enforcementLevel"
            # Last component is the key
            return offset_uri.split('/')[-1]

        # Secondary: Use displayName or name field
        display_name = definition.get('displayName', '')
        if display_name:
            # Often the display name IS the key
            return display_name

        name = definition.get('name', '')
        if name:
            # Name might be like "enforcementLevel (antivirusEngine)"
            if '(' in name:
                return name.split('(')[0].strip()
            return name

        return None

    def resolve_choice_value(self, choice_value_id: str, setting_id: str) -> Any:
        """Resolve enumeration ID to actual value, converting string booleans to real booleans"""
        definition = self.get_setting_definition(setting_id)
        if not definition:
            return None

        options = definition.get('options', [])
        for option in options:
            if option.get('itemId') == choice_value_id:
                option_value = option.get('optionValue', {})
                value = option_value.get('value')

                # Convert string booleans to actual booleans for proper plist output
                # Graph API schema stores these as strings "true"/"false"
                if isinstance(value, str):
                    if value.lower() == 'true':
                        return True
                    elif value.lower() == 'false':
                        return False

                return value

        # Value not found in options
        logger.warning(f"Choice value '{choice_value_id}' not found in schema for {setting_id}")
        return None

    def parse_base_uri(self, setting_id: str) -> tuple[Optional[str], Optional[str]]:
        """
        Parse baseUri to extract PayloadType and parent dictionary path.

        For Microsoft settings (Defender, Edge, Office):
            baseUri format: PayloadContent/com.microsoft.wdav/Forced/[0]/mcx_preference_settings
            Components: PayloadType (com.microsoft.wdav), Parent dict (antivirusEngine)

        For Apple native settings (SoftwareUpdate, FileVault, etc.):
            baseUri is empty, so derive PayloadType from setting ID prefix.
            e.g., com.apple.softwareupdate_automaticdownload -> com.apple.SoftwareUpdate

        Returns: (payload_type, parent_path) or (None, None) if not parseable
        """
        definition = self.get_setting_definition(setting_id)
        if not definition:
            return None, None

        base_uri = definition.get('baseUri', '')

        # If baseUri is populated (Microsoft settings), parse it
        if base_uri:
            parts = base_uri.split('/')
            payload_type = None
            parent_path = None

            if len(parts) >= 2 and parts[0] == 'PayloadContent':
                payload_type = parts[1]  # e.g., "com.microsoft.wdav"

            # Extract parent path (after mcx_preference_settings)
            if 'mcx_preference_settings' in base_uri:
                after_mcx = base_uri.split('mcx_preference_settings/')
                if len(after_mcx) > 1 and after_mcx[1]:
                    parent_path = after_mcx[1].split('/')[0]

            return payload_type, parent_path

        # For Apple native settings, derive PayloadType from setting ID
        # Format: com.apple.softwareupdate_automaticdownload
        #         ^^^^^^^^^^^^^^^^^^^^^^^^ <- domain becomes PayloadType
        if setting_id.startswith('com.apple.'):
            # Extract the domain part before the last underscore-separated key
            # com.apple.softwareupdate_automaticdownload -> com.apple.softwareupdate
            parts = setting_id.split('_')
            if len(parts) >= 2:
                domain = parts[0]  # com.apple.softwareupdate

                # Convert to proper PayloadType casing
                # com.apple.softwareupdate -> com.apple.SoftwareUpdate
                payload_type = self._normalize_apple_payload_type(domain)
                return payload_type, None

        # Workaround for Microsoft Graph API bug: some settings are missing
        # the com.apple. prefix (e.g., loginwindow_* instead of com.apple.loginwindow_*)
        # Map known malformed setting prefixes to their correct PayloadType
        malformed_prefix_mappings = {
            'loginwindow_': 'com.apple.loginwindow',
            'screensaver_': 'com.apple.screensaver',
        }
        for prefix, payload_type in malformed_prefix_mappings.items():
            if setting_id.startswith(prefix):
                return payload_type, None

        return None, None

    def _normalize_apple_payload_type(self, domain: str) -> str:
        """
        Normalize Apple domain to proper PayloadType format.

        Known mappings (Apple's actual PayloadType identifiers):
        - com.apple.softwareupdate -> com.apple.SoftwareUpdate
        - com.apple.applicationaccess -> com.apple.applicationaccess (lowercase)
        - com.apple.mcx.filevault2 -> com.apple.MCX.FileVault2
        - com.apple.security.firewall -> com.apple.security.firewall
        - com.apple.loginwindow -> com.apple.loginwindow
        - com.apple.screensaver -> com.apple.screensaver
        """
        # Known PayloadType mappings (domain -> actual PayloadType)
        known_mappings = {
            'com.apple.softwareupdate': 'com.apple.SoftwareUpdate',
            'com.apple.mcx.filevault2': 'com.apple.MCX.FileVault2',
            'com.apple.mcx': 'com.apple.MCX',
            'com.apple.extensiblesso': 'com.apple.extensiblesso',
            'com.apple.applicationaccess': 'com.apple.applicationaccess',
            'com.apple.security.firewall': 'com.apple.security.firewall',
            'com.apple.loginwindow': 'com.apple.loginwindow',
            'com.apple.screensaver': 'com.apple.screensaver',
            'com.apple.systempolicy.control': 'com.apple.systempolicy.control',
            'com.apple.eas.account': 'com.apple.eas.account',
            'com.apple.configurationprofile.identification': (
                'com.apple.configurationprofile.identification'
            ),
        }

        if domain in known_mappings:
            return known_mappings[domain]

        # Default: return as-is (most Apple domains are lowercase)
        return domain

    def get_payload_type(self, setting_id: str) -> Optional[str]:
        """Get the correct PayloadType from schema baseUri"""
        payload_type, _ = self.parse_base_uri(setting_id)
        return payload_type

    def get_parent_dict(self, setting_id: str) -> Optional[str]:
        """Get the parent dictionary name for nesting (e.g., 'antivirusEngine')"""
        _, parent = self.parse_base_uri(setting_id)
        return parent

    def report_missing_settings(self) -> bool:
        """Report any settings that were not found in schema. Returns True if any missing."""
        if self.missing_settings:
            logger.error("=" * 70)
            logger.error("SCHEMA MISSING SETTINGS - Conversion may be incomplete!")
            logger.error("=" * 70)
            logger.error("The following settings were not found in the Graph API schema:")
            for setting_id in sorted(self.missing_settings):
                logger.error(f"  - {setting_id}")
            logger.error("")
            logger.error(
                "To fix: Re-run ./scripts/fetch-graph-schema.sh to update the schema cache"
            )
            logger.error("=" * 70)
            return True
        return False


@dataclass
class ConvertedSetting:
    """Result of converting a single setting"""
    key: Optional[str]
    value: Any
    parent_dict: Optional[str]  # e.g., "antivirusEngine", "cloudService"
    payload_type: Optional[str]  # e.g., "com.microsoft.wdav"


class SettingConverter:
    """Converts Microsoft Graph API settings to Apple plist format using schema"""

    def __init__(self, schema_loader: GraphSchemaLoader):
        self.schema_loader = schema_loader
        self.conversion_errors: list[str] = []

    def extract_setting_key(self, setting_id: str) -> Optional[str]:
        """
        Extract the actual setting key from the settingDefinitionId using schema.

        Returns None if setting is not in schema (will be tracked as missing).
        """
        plist_key = self.schema_loader.resolve_plist_key(setting_id)
        if plist_key:
            logger.debug(f"Resolved {setting_id} -> {plist_key}")
            return plist_key

        # Setting not in schema - already tracked by schema_loader
        self.conversion_errors.append(f"Unknown setting: {setting_id}")
        return None

    def get_nesting_info(self, setting_id: str) -> tuple[Optional[str], Optional[str]]:
        """Get payload_type and parent_dict for a setting"""
        return self.schema_loader.parse_base_uri(setting_id)

    def convert_choice_setting(self, setting: dict[str, Any]) -> ConvertedSetting:
        """Convert a choice setting to plist key-value pair"""
        setting_def_id = setting.get('settingDefinitionId', '')
        choice_value = setting.get('choiceSettingValue', {})
        value_str = choice_value.get('value', '')

        key = self.extract_setting_key(setting_def_id)
        payload_type, parent_dict = self.get_nesting_info(setting_def_id)

        if key is None:
            return ConvertedSetting(None, None, parent_dict, payload_type)

        # Resolve value from schema
        resolved_value = self.schema_loader.resolve_choice_value(value_str, setting_def_id)
        if resolved_value is not None:
            logger.debug(f"Resolved choice value: {value_str} -> {resolved_value}")
            return ConvertedSetting(key, resolved_value, parent_dict, payload_type)

        # Value not in schema - log error but continue
        self.conversion_errors.append(
            f"Unknown choice value for {setting_def_id}: {value_str}"
        )
        return ConvertedSetting(key, None, parent_dict, payload_type)

    def convert_string_setting(self, setting: dict[str, Any]) -> ConvertedSetting:
        """Convert a string setting to plist key-value pair"""
        setting_def_id = setting.get('settingDefinitionId', '')
        simple_value = setting.get('simpleSettingValue', {})
        string_value = simple_value.get('value')

        key = self.extract_setting_key(setting_def_id)
        payload_type, parent_dict = self.get_nesting_info(setting_def_id)

        if key is None or string_value is None:
            return ConvertedSetting(None, None, parent_dict, payload_type)

        return ConvertedSetting(key, string_value, parent_dict, payload_type)

    def convert_integer_setting(self, setting: dict[str, Any]) -> ConvertedSetting:
        """Convert an integer setting to plist key-value pair"""
        setting_def_id = setting.get('settingDefinitionId', '')
        simple_value = setting.get('simpleSettingValue', {})
        int_value = simple_value.get('value')

        key = self.extract_setting_key(setting_def_id)
        payload_type, parent_dict = self.get_nesting_info(setting_def_id)

        if key is None or int_value is None:
            return ConvertedSetting(None, None, parent_dict, payload_type)

        return ConvertedSetting(key, int(int_value), parent_dict, payload_type)

    def convert_collection_setting(self, setting: dict[str, Any]) -> ConvertedSetting:
        """Convert a collection setting to plist array"""
        setting_def_id = setting.get('settingDefinitionId', '')
        collection_values = setting.get('simpleSettingCollectionValue')

        key = self.extract_setting_key(setting_def_id)
        payload_type, parent_dict = self.get_nesting_info(setting_def_id)

        # Skip if no key or no collection values
        if key is None or collection_values is None or len(collection_values) == 0:
            return ConvertedSetting(None, None, parent_dict, payload_type)

        values = [item.get('value') for item in collection_values if item.get('value') is not None]
        if not values:
            return ConvertedSetting(None, None, parent_dict, payload_type)
        return ConvertedSetting(key, values, parent_dict, payload_type)

    def convert_group_setting_children(self, setting: dict[str, Any]) -> dict[str, Any]:
        """Convert children of a group setting to nested plist dict (no nesting info needed)"""
        children = setting.get('children', [])
        result = {}

        for child in children:
            odata_type = child.get('@odata.type', '')

            if 'Choice' in odata_type:
                converted = self.convert_choice_setting(child)
                if converted.key is not None and converted.value is not None:
                    result[converted.key] = converted.value
            elif 'SimpleSettingCollectionInstance' in odata_type:
                converted = self.convert_collection_setting(child)
                if converted.key is not None and converted.value is not None:
                    result[converted.key] = converted.value
            elif 'SimpleSettingInstance' in odata_type:
                # Handle generic simple settings (e.g., ExtensionIdentifier, RegistrationToken)
                converted = self.convert_simple_setting(child)
                if converted.key is not None and converted.value is not None:
                    result[converted.key] = converted.value
            elif 'GroupSettingCollectionInstance' in odata_type:
                # Handle nested group collections (e.g., PlatformSSO, ExtensionData)
                setting_def_id = child.get('settingDefinitionId', '')
                group_values = child.get('groupSettingCollectionValue', [])
                key = self.extract_setting_key(setting_def_id)

                if key and group_values:
                    # Check for generic key-value pattern (ExtensionData uses this)
                    # Pattern: each group has keytobereplaced + typepicker with actual value
                    is_generic_kv = any(
                        'generickey_keytobereplaced' in c.get('settingDefinitionId', '')
                        for group in group_values
                        for c in group.get('children', [])
                    )

                    if is_generic_kv:
                        # Convert to flat dictionary with dynamic keys
                        kv_dict = {}
                        for group in group_values:
                            kv_pair = self._convert_generic_key_value(group)
                            if kv_pair:
                                kv_dict[kv_pair[0]] = kv_pair[1]
                        if kv_dict:
                            result[key] = kv_dict
                    else:
                        # Recursively convert nested groups
                        # Check schema to determine if array or dict type
                        child_ids = self.schema_loader.schema.get('settings', {}).get(
                            setting_def_id, {}
                        ).get('childIds', [])
                        is_array_type = any('_item_' in cid.lower() for cid in child_ids)

                        nested_groups = []
                        for group in group_values:
                            nested_result = self.convert_group_setting_children(group)
                            if nested_result:
                                nested_groups.append(nested_result)

                        if is_array_type and nested_groups:
                            result[key] = nested_groups
                        elif len(nested_groups) == 1:
                            result[key] = nested_groups[0]
                        elif len(nested_groups) > 1:
                            # Merge multiple dicts
                            merged = {}
                            for g in nested_groups:
                                merged.update(g)
                            result[key] = merged
            elif 'String' in odata_type:
                converted = self.convert_string_setting(child)
                if converted.key is not None:
                    result[converted.key] = converted.value
            elif 'Integer' in odata_type:
                converted = self.convert_integer_setting(child)
                if converted.key is not None:
                    result[converted.key] = converted.value

        return result

    def _convert_generic_key_value(self, group: dict[str, Any]) -> Optional[tuple]:
        """
        Convert a generic key-value group to a (key, value) tuple.

        Pattern used by ExtensionData and similar:
        - generickey_keytobereplaced: contains the dynamic key name
        - $typepicker choice: determines value type (string/integer)
        - generickey_string or generickey_integer: contains the actual value
        """
        children = group.get('children', [])
        key_name = None
        value = None

        for child in children:
            setting_id = child.get('settingDefinitionId', '')

            if 'keytobereplaced' in setting_id:
                # This contains the dynamic key name
                simple_val = child.get('simpleSettingValue', {})
                key_name = simple_val.get('value')

            elif 'typepicker' in setting_id or 'ignored' in setting_id:
                # This choice contains the actual value in its children
                choice_val = child.get('choiceSettingValue', {})
                for choice_child in choice_val.get('children', []):
                    choice_child_id = choice_child.get('settingDefinitionId', '')
                    if 'generickey_string' in choice_child_id:
                        simple_val = choice_child.get('simpleSettingValue', {})
                        value = simple_val.get('value')
                    elif 'generickey_integer' in choice_child_id:
                        simple_val = choice_child.get('simpleSettingValue', {})
                        value = simple_val.get('value')

        if key_name is not None and value is not None:
            return (key_name, value)
        return None

    def convert_simple_setting(self, setting: dict[str, Any]) -> ConvertedSetting:
        """Convert a simple setting (generic) to plist key-value pair"""
        setting_def_id = setting.get('settingDefinitionId', '')
        simple_value = setting.get('simpleSettingValue', {})

        key = self.extract_setting_key(setting_def_id)
        payload_type, parent_dict = self.get_nesting_info(setting_def_id)

        if key is None:
            return ConvertedSetting(None, None, parent_dict, payload_type)

        # Determine value type from @odata.type in simpleSettingValue
        value_type = simple_value.get('@odata.type', '')
        raw_value = simple_value.get('value')

        # Skip if value is missing (Not Configured)
        if raw_value is None:
            return ConvertedSetting(None, None, parent_dict, payload_type)

        if 'StringSettingValue' in value_type:
            # Check if string is actually a boolean
            bool_val = parse_bool(raw_value)
            if bool_val is not None:
                return ConvertedSetting(key, bool_val, parent_dict, payload_type)
            return ConvertedSetting(key, str(raw_value), parent_dict, payload_type)
        elif 'IntSettingValue' in value_type or 'IntegerSettingValue' in value_type:
            return ConvertedSetting(key, int(raw_value), parent_dict, payload_type)
        elif 'BoolSettingValue' in value_type:
            bool_val = parse_bool(raw_value)
            if bool_val is None:
                return ConvertedSetting(None, None, parent_dict, payload_type)
            return ConvertedSetting(key, bool_val, parent_dict, payload_type)
        else:
            return ConvertedSetting(key, raw_value, parent_dict, payload_type)

    def convert_setting_instance(self, setting_instance: dict[str, Any]) -> ConvertedSetting:
        """Convert a setting instance to plist format with nesting info"""
        odata_type = setting_instance.get('@odata.type', '')

        if 'ChoiceSettingInstance' in odata_type:
            return self.convert_choice_setting(setting_instance)

        elif 'StringSettingInstance' in odata_type:
            return self.convert_string_setting(setting_instance)

        elif 'IntegerSettingInstance' in odata_type:
            return self.convert_integer_setting(setting_instance)

        elif 'SimpleSettingInstance' in odata_type:
            return self.convert_simple_setting(setting_instance)

        elif 'SimpleSettingCollectionInstance' in odata_type:
            return self.convert_collection_setting(setting_instance)

        elif 'GroupSettingCollectionInstance' in odata_type:
            setting_def_id = setting_instance.get('settingDefinitionId', '')
            group_values = setting_instance.get('groupSettingCollectionValue', [])

            converted_groups = []
            for group in group_values:
                converted = self.convert_group_setting_children(group)
                if converted:  # Only add non-empty groups
                    converted_groups.append(converted)

            key = self.extract_setting_key(setting_def_id)
            payload_type, parent_dict = self.get_nesting_info(setting_def_id)

            if key is None:
                return ConvertedSetting(None, None, parent_dict, payload_type)

            # Check if this is an Apple native settings group wrapper
            # These are organisational containers in Intune but should be flattened
            # Formats:
            #   com.apple.softwareupdate_com.apple.softwareupdate (exact match)
            #   com.apple.mcx_com.apple.mcx-accounts (domain with suffix)
            #   loginwindow_loginwindow (legacy format)
            is_apple_wrapper = False
            if '_' in setting_def_id:
                parts = setting_def_id.split('_', 1)  # Split only on first underscore
                prefix = parts[0]
                suffix = parts[1] if len(parts) > 1 else ''

                # Check for exact match or suffix starts with prefix
                # e.g., com.apple.mcx vs com.apple.mcx-accounts
                if prefix.startswith('com.apple.') or prefix == 'loginwindow':
                    is_apple_wrapper = suffix.startswith(prefix) or suffix == prefix

            if is_apple_wrapper:
                # For Apple wrappers, use special key "__flatten__" to signal
                # that children should be merged directly into payload
                logger.debug(f"Apple wrapper detected: {setting_def_id} - flattening children")
                if len(converted_groups) == 1:
                    return ConvertedSetting("__flatten__", converted_groups[0], None, payload_type)
                elif len(converted_groups) > 1:
                    # Merge all groups into single dict
                    merged = {}
                    for g in converted_groups:
                        merged.update(g)
                    return ConvertedSetting("__flatten__", merged, None, payload_type)
                else:
                    return ConvertedSetting("__flatten__", {}, None, payload_type)

            # Determine if this is an array or dict based on schema structure:
            # - Graph children with "_item_" pattern = array (e.g., Rules_item_Comment)
            # - Graph children with named keys = dict (e.g., Services_SystemPolicyAllFiles)
            #
            # We detect this by checking the child setting IDs in the Graph schema
            child_ids = self.schema_loader.schema.get('settings', {}).get(
                setting_def_id, {}
            ).get('childIds', [])

            # If childIds contain "_item_" pattern, it's an array of items
            # If childIds are named (like "services_systempolicyallfiles"), it's a dict
            is_array_type = any('_item_' in cid.lower() for cid in child_ids)

            if is_array_type:
                # Array type: return list directly
                return ConvertedSetting(key, converted_groups, parent_dict, payload_type)
            elif len(converted_groups) == 1:
                # Dict type with single group: unwrap
                return ConvertedSetting(key, converted_groups[0], parent_dict, payload_type)
            elif len(converted_groups) > 1:
                # Dict type with multiple groups: merge (shouldn't normally happen)
                merged = {}
                for g in converted_groups:
                    merged.update(g)
                return ConvertedSetting(key, merged, parent_dict, payload_type)
            else:
                return ConvertedSetting(key, {}, parent_dict, payload_type)

        else:
            self.conversion_errors.append(f"Unknown setting type: {odata_type}")
            return ConvertedSetting(None, None, None, None)

    def report_errors(self) -> bool:
        """Report conversion errors. Returns True if any errors."""
        if self.conversion_errors:
            logger.warning("Conversion completed with errors:")
            for error in self.conversion_errors:
                logger.warning(f"  - {error}")
            return True
        return False


class MobileconfigGenerator:
    """Generates Apple Configuration Profile (mobileconfig) files"""

    def __init__(self, converter: SettingConverter, schema_loader: GraphSchemaLoader):
        self.converter = converter
        self.schema_loader = schema_loader

    def convert_json_to_mobileconfig(
        self,
        json_data: dict[str, Any],
        organization: str = "Talieisin",
        custom_payload_type: Optional[str] = None,
        scope: str = "System",
        removal_disallowed: bool = True
    ) -> dict[str, Any]:
        """
        Convert OpenIntuneBaseline JSON to mobileconfig plist format.

        Handles multiple PayloadTypes by creating separate inner payloads for each.
        - Apple settings: Each domain (com.apple.applicationaccess, etc.) gets its own payload
        - Microsoft settings: Nested under parent_dict within a single payload

        Args:
            json_data: Parsed JSON from OIB profile
            organization: Organization name for PayloadOrganization
            custom_payload_type: Override automatic PayloadType detection (single payload only)
            scope: PayloadScope - "System" or "User"
            removal_disallowed: Whether profile can be removed by user

        Returns:
            Dictionary representing mobileconfig plist
        """
        settings = json_data.get('settings', [])
        name = json_data.get('name', 'Converted Profile')
        description = json_data.get('description', '')

        # Convert all settings and collect nesting info
        converted_settings: list[ConvertedSetting] = []

        for setting_item in settings:
            setting_instance = setting_item.get('settingInstance', {})
            converted = self.converter.convert_setting_instance(setting_instance)
            converted_settings.append(converted)

        # Group settings by PayloadType
        # Structure: {payload_type: {"nested": {parent: {key: val}}, "root": {key: val}}}
        payloads_by_type: dict[str, dict[str, Any]] = {}

        for converted in converted_settings:
            if converted.key is None or converted.value is None:
                continue

            # Determine PayloadType for this setting
            pt = custom_payload_type or converted.payload_type or "UNKNOWN_PAYLOAD_TYPE"

            if pt not in payloads_by_type:
                payloads_by_type[pt] = {"nested": {}, "root": {}}

            # Handle "__flatten__" - Apple wrapper, merge contents to root of PayloadType
            if converted.key == "__flatten__" and isinstance(converted.value, dict):
                flattened = converted.value.copy()
                # Remap DisabledPreferencePanes to DisabledSystemSettings for macOS 13+
                if 'DisabledPreferencePanes' in flattened:
                    values = flattened['DisabledPreferencePanes']
                    is_macos13 = isinstance(values, list) and any(
                        '.extension' in str(v) or 'SettingsExtension' in str(v)
                        for v in values
                    )
                    if is_macos13:
                        logger.info(
                            "Remapping DisabledPreferencePanes to DisabledSystemSettings "
                            "(macOS 13+ values detected)"
                        )
                        flattened['DisabledSystemSettings'] = flattened.pop(
                            'DisabledPreferencePanes'
                        )
                payloads_by_type[pt]["root"].update(flattened)
                logger.debug(f"Flattened Apple wrapper with {len(flattened)} settings to {pt}")
            elif converted.parent_dict:
                # Microsoft nested setting (antivirusEngine, cloudService, etc.)
                if converted.parent_dict not in payloads_by_type[pt]["nested"]:
                    payloads_by_type[pt]["nested"][converted.parent_dict] = {}
                nested_dict = payloads_by_type[pt]["nested"][converted.parent_dict]
                nested_dict[converted.key] = converted.value
                logger.debug(f"Nested {converted.key} under {converted.parent_dict} in {pt}")
            else:
                # Root-level setting
                payloads_by_type[pt]["root"][converted.key] = converted.value

        # Payload types that cannot be converted to standalone mobileconfig
        # These require Intune to inject additional data at deploy time
        UNSUPPORTED_PAYLOAD_TYPES = {
            'com.apple.security.fderecoverykeyescrow': (
                "FileVault Recovery Key Escrow requires EncryptCertPayloadUUID and a "
                "certificate payload that Intune injects automatically at deploy time. "
                "This payload cannot function as a standalone mobileconfig."
            ),
        }

        # Build inner payloads for each PayloadType
        inner_payloads = []
        for payload_type, content in payloads_by_type.items():
            if payload_type == "UNKNOWN_PAYLOAD_TYPE":
                logger.warning("Settings with unknown PayloadType will be skipped")
                continue

            # Skip unsupported payload types that can't work standalone
            if payload_type in UNSUPPORTED_PAYLOAD_TYPES:
                reason = UNSUPPORTED_PAYLOAD_TYPES[payload_type]
                logger.warning(f"Skipping {payload_type}: {reason}")
                continue

            # Skip if no actual content
            if not content["root"] and not content["nested"]:
                continue

            inner_payload = {
                'PayloadType': payload_type,
                'PayloadVersion': 1,
                'PayloadIdentifier': f"{payload_type}.{uuid.uuid4()}",
                'PayloadUUID': str(uuid.uuid4()).upper(),
                'PayloadDisplayName': name.split(' - ')[-1] if ' - ' in name else name,
            }

            if description:
                inner_payload['PayloadDescription'] = description

            # Add nested dictionaries (Microsoft settings like antivirusEngine)
            for parent_dict, child_settings in content["nested"].items():
                inner_payload[parent_dict] = child_settings
                logger.debug(
                    f"Added {parent_dict} with {len(child_settings)} settings to {payload_type}"
                )

            # Add root-level settings (Apple flattened or direct settings)
            inner_payload.update(content["root"])

            inner_payloads.append(inner_payload)
            root_count = len(content['root'])
            nested_count = len(content['nested'])
            logger.info(
                f"Created payload for {payload_type} with {root_count} root + {nested_count} nested"
            )

        if not inner_payloads:
            logger.error("No valid payloads generated!")
            # Create empty payload to avoid completely broken output
            inner_payloads = [{
                'PayloadType': custom_payload_type or "UNKNOWN_PAYLOAD_TYPE",
                'PayloadVersion': 1,
                'PayloadIdentifier': f"empty.{uuid.uuid4()}",
                'PayloadUUID': str(uuid.uuid4()).upper(),
                'PayloadEnabled': True,
                'PayloadDisplayName': "Empty Payload",
            }]

        # Build outer configuration profile
        mobileconfig = {
            'PayloadType': 'Configuration',
            'PayloadVersion': 1,
            'PayloadIdentifier': f"com.talieisin.{uuid.uuid4()}",
            'PayloadUUID': str(uuid.uuid4()).upper(),
            'PayloadDisplayName': name,
            'PayloadDescription': description,
            'PayloadOrganization': organization,
            'PayloadScope': scope,
            'PayloadRemovalDisallowed': removal_disallowed,
            'PayloadContent': inner_payloads
        }

        return mobileconfig

    def write_mobileconfig(self, mobileconfig: dict[str, Any], output_path: Path):
        """Write mobileconfig dictionary to XML plist file"""
        try:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, 'wb') as f:
                plistlib.dump(mobileconfig, f, fmt=plistlib.FMT_XML)
            logger.info(f"Wrote: {output_path}")
        except Exception as e:
            logger.error(f"Failed to write mobileconfig: {e}")
            raise


class BatchConverter:
    """Handles batch conversion using a mapping file"""

    def __init__(
        self,
        mapping_path: Path,
        output_root: Path,
        organization_override: Optional[str] = None
    ):
        self.mapping_path = mapping_path
        self.output_root = output_root
        self.mapping = self.load_mapping()
        self.organization_override = organization_override

        # Load config from mapping.yaml
        config = self.mapping.get('config', {})
        self.organization = (
            organization_override or
            config.get('organization') or
            'Talieisin'
        )
        self.default_scope = config.get('default_scope', 'System')
        self.removal_disallowed = config.get('removal_disallowed', True)

    def load_mapping(self) -> dict[str, Any]:
        """Load YAML mapping file"""
        try:
            with open(self.mapping_path) as f:
                return yaml.safe_load(f)
        except Exception as e:
            logger.error(f"Failed to load mapping file: {e}")
            raise

    def convert_all(
        self,
        converter: SettingConverter,
        generator: MobileconfigGenerator
    ) -> tuple[int, int]:
        """Convert all profiles defined in mapping. Returns (success_count, fail_count)"""
        profiles = self.mapping.get('profiles', [])

        logger.info(f"Processing {len(profiles)} profiles from mapping file...")
        logger.info(f"Output directory: {self.output_root}")

        success_count = 0
        fail_count = 0

        for profile in profiles:
            oib_name = profile.get('oib_name')
            output_path = profile.get('output_path')
            custom_payload_type = profile.get('payload_type')
            enabled = profile.get('enabled', True)

            if not enabled:
                logger.info(f"Skipping disabled profile: {oib_name}")
                continue

            if not oib_name or not output_path:
                logger.warning(f"Invalid profile entry: {profile}")
                fail_count += 1
                continue

            try:
                self.convert_profile(
                    oib_name=oib_name,
                    output_path=output_path,
                    converter=converter,
                    generator=generator,
                    custom_payload_type=custom_payload_type
                )
                success_count += 1
            except Exception as e:
                logger.error(f"Failed to convert {oib_name}: {e}")
                fail_count += 1

        logger.info(f"Batch conversion complete: {success_count} succeeded, {fail_count} failed")
        return success_count, fail_count

    def convert_profile(
        self,
        oib_name: str,
        output_path: str,
        converter: SettingConverter,
        generator: MobileconfigGenerator,
        custom_payload_type: Optional[str] = None
    ):
        """Convert a single profile from OIB to mobileconfig"""
        # Construct OIB JSON URL
        base_url = "https://raw.githubusercontent.com/SkipToTheEndpoint/OpenIntuneBaseline/main/MACOS/NativeImport"
        json_url = f"{base_url}/{oib_name}.json"

        logger.info(f"Downloading: {oib_name}")

        try:
            response = requests.get(json_url, timeout=30)
            response.raise_for_status()

            # Handle UTF-8 BOM
            content = response.content
            if content.startswith(b'\xef\xbb\xbf'):
                content = content[3:]

            json_data = json.loads(content.decode('utf-8'))

        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 404:
                raise Exception(f"Profile not found on OIB GitHub: {oib_name}") from e
            raise
        except Exception as e:
            logger.error(f"Failed to download {oib_name}: {e}")
            raise

        logger.info(f"Converting: {oib_name}")
        mobileconfig = generator.convert_json_to_mobileconfig(
            json_data,
            organization=self.organization,
            custom_payload_type=custom_payload_type,
            scope=self.default_scope,
            removal_disallowed=self.removal_disallowed
        )

        # Resolve output path relative to output root
        full_output_path = self.output_root / output_path
        generator.write_mobileconfig(mobileconfig, full_output_path)


def main():
    parser = argparse.ArgumentParser(
        description='Convert OpenIntuneBaseline JSON profiles to mobileconfig format',
        epilog='REQUIRES Graph API schema cache. Run: ./scripts/fetch-graph-schema.sh first'
    )

    parser.add_argument(
        '--profile',
        type=Path,
        help='Path to OIB JSON profile file'
    )

    parser.add_argument(
        '--output',
        type=Path,
        help='Output path for mobileconfig file'
    )

    parser.add_argument(
        '--batch',
        action='store_true',
        help='Run batch conversion using mapping file'
    )

    # Determine repo root (two levels up from src/oib_converter/)
    repo_root = Path(__file__).parent.parent.parent

    parser.add_argument(
        '--mapping',
        type=Path,
        default=repo_root / 'mapping.yaml',
        help='Path to mapping YAML file (default: mapping.yaml)'
    )

    parser.add_argument(
        '--output-dir',
        type=Path,
        default=repo_root / 'output',
        help='Output directory for batch conversion (default: output/)'
    )

    parser.add_argument(
        '--schema',
        type=Path,
        default=repo_root / 'cache' / 'graph-schema.json',
        help='Path to Graph API schema JSON (default: cache/graph-schema.json)'
    )

    parser.add_argument(
        '--organisation',
        type=str,
        default='Talieisin',
        help='Organisation name for mobileconfig (default: Talieisin)'
    )

    parser.add_argument(
        '--payload-type',
        type=str,
        help='Override PayloadType (recommended for accurate conversion)'
    )

    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Enable verbose logging'
    )

    args = parser.parse_args()

    # Configure logging (only in main, not on import)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )

    # Check dependencies
    _check_dependencies()

    # Load Graph API schema - REQUIRED
    try:
        schema_loader = GraphSchemaLoader(args.schema)
    except SchemaError as e:
        logger.error(str(e))
        sys.exit(1)

    # Initialise converter and generator
    converter = SettingConverter(schema_loader)
    generator = MobileconfigGenerator(converter, schema_loader)

    exit_code = 0

    if args.batch:
        # Batch mode
        if not args.mapping.exists():
            logger.error(f"Mapping file not found: {args.mapping}")
            sys.exit(1)

        # Pass CLI organisation if explicitly provided (not default)
        org_override = args.organisation if args.organisation != 'Talieisin' else None
        batch = BatchConverter(args.mapping, args.output_dir, org_override)
        success, fail = batch.convert_all(converter, generator)

        if fail > 0:
            exit_code = 1

    elif args.profile and args.output:
        # Single file mode
        if not args.profile.exists():
            logger.error(f"Profile file not found: {args.profile}")
            sys.exit(1)

        logger.info(f"Converting: {args.profile}")

        with open(args.profile) as f:
            # Handle UTF-8 BOM
            content = f.read()
            if content.startswith('\ufeff'):
                content = content[1:]
            json_data = json.loads(content)

        mobileconfig = generator.convert_json_to_mobileconfig(
            json_data,
            organization=args.organisation,
            custom_payload_type=args.payload_type
        )

        generator.write_mobileconfig(mobileconfig, args.output)

    else:
        parser.print_help()
        sys.exit(1)

    # Report any issues
    if converter.report_errors():
        exit_code = 1

    if schema_loader.report_missing_settings():
        exit_code = 1

    sys.exit(exit_code)


if __name__ == '__main__':
    main()
