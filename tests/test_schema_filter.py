"""Exercise the schema fetcher's embedded Python with a synthetic Graph response."""

import json
from pathlib import Path

import requests


def test_platform_metadata_takes_precedence_over_identifier(monkeypatch, capsys):
    definitions = [
        {"id": "com.apple.ios", "applicability": {"platform": "iOS"}},
        {"id": "microsoft.windows", "applicability": {"platform": "windows10"}},
        {"id": "app_privacy_permissiondefaults", "applicability": {"platform": "macOS"}},
        {"id": "enforcement_update", "applicability": {"platform": "iOS, macOS"}},
        {"id": "softwareupdate_actions", "applicability": {"platform": "macOS"}},
        {"id": "com.apple.legacy"},
        {"id": "office.empty", "applicability": {"platform": ""}},
        {"id": "edge.null", "applicability": {"platform": None}},
        {"id": "unrelated"},
    ]

    class Response:
        def raise_for_status(self):
            pass

        def json(self):
            return {"value": definitions}

    monkeypatch.setattr(requests, "get", lambda *args, **kwargs: Response())
    monkeypatch.setenv("GRAPH_URL", "https://graph.example.test/settings")
    monkeypatch.setenv("ACCESS_TOKEN", "synthetic-test-token")
    script = Path(__file__).parents[1] / "scripts/fetch-graph-schema.sh"
    python_source = script.read_text().split(
        '> "$OUTPUT_FILE" <<\'EOF\'\n', 1
    )[1].split("\nEOF\n", 1)[0]
    exec(compile(python_source, str(script), "exec"), {})
    output = json.loads(capsys.readouterr().out)
    assert set(output["settings"]) == {
        "app_privacy_permissiondefaults", "enforcement_update", "softwareupdate_actions",
        "com.apple.legacy", "office.empty", "edge.null",
    }
    assert output["total_settings"] == 6
