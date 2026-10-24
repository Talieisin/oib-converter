"""Run fetch-graph-schema.sh end to end with fake msal and requests modules.

No network and no real credentials: the script is copied into a temporary repo
root whose .venv/bin/python3 runs this interpreter with fake ``msal`` and
``requests`` packages first on PYTHONPATH. The fakes record what the script
did (whether MSAL was imported, which `Authorization` header reached "Graph",
whether GRAPH_ACCESS_TOKEN leaked into a child's environment) in JSON files.
"""

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).parents[1] / "scripts/fetch-graph-schema.sh"

# Synthetic three-segment base64url values, the shape the script accepts. They
# deliberately do not start with "eyJ", so secret scanners do not read them as
# JWTs. None of them is a real token.
SUPPLIED_TOKEN = "synthetic-supplied-header.synthetic-supplied-payload.synthetic-supplied-sig"
MSAL_TOKEN = "synthetic-msal-header.synthetic-msal-payload.synthetic-msal-sig"
CLIENT_SECRET = "synthetic-client-secret-value"
CLIENT_ID = "11111111-2222-3333-4444-555555555555"
TENANT_ID = "66666666-7777-8888-9999-000000000000"

FAKE_MSAL = """
import json, os

with open(os.environ["FAKE_MSAL_LOG"], "a") as log:
    log.write(json.dumps({"event": "import"}) + "\\n")


class ConfidentialClientApplication:
    def __init__(self, client_id, authority=None, client_credential=None):
        with open(os.environ["FAKE_MSAL_LOG"], "a") as log:
            log.write(json.dumps({
                "event": "client",
                "client_id": client_id,
                "authority": authority,
                "secret_matches": client_credential == os.environ.get("EXPECT_SECRET"),
            }) + "\\n")

    def acquire_token_for_client(self, scopes):
        return {"access_token": os.environ["FAKE_MSAL_TOKEN"], "token_type": "Bearer"}
"""

FAKE_REQUESTS = """
import json, os


class exceptions:
    class RequestException(Exception):
        pass

    class HTTPError(RequestException):
        def __init__(self, message, response=None):
            super().__init__(message)
            self.response = response

    class ConnectionError(RequestException):
        pass

    class Timeout(RequestException):
        pass

    class ChunkedEncodingError(RequestException):
        pass


class _Response:
    def __init__(self, status_code):
        self.status_code = status_code
        self.headers = {}

    def raise_for_status(self):
        if self.status_code >= 400:
            raise exceptions.HTTPError(f"{self.status_code} Error", response=self)

    def json(self):
        return {"value": [{"id": "softwareupdate_actions", "applicability": {"platform": "macOS"}}]}


def get(url, headers=None, timeout=None):
    with open(os.environ["FAKE_REQUESTS_LOG"], "a") as log:
        log.write(json.dumps({
            "url": url,
            "authorization": (headers or {}).get("Authorization"),
            "graph_access_token_in_env": "GRAPH_ACCESS_TOKEN" in os.environ,
        }) + "\\n")
    return _Response(int(os.environ.get("FAKE_GRAPH_STATUS", "200")))
"""


def _read_log(path):
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines()]


@pytest.fixture
def sandbox(tmp_path):
    bash = shutil.which("bash")
    jq = shutil.which("jq")
    if bash is None or jq is None:
        pytest.skip("bash and jq are required to run fetch-graph-schema.sh")

    root = tmp_path / "repo"
    (root / "scripts").mkdir(parents=True)
    shutil.copy2(SCRIPT, root / "scripts/fetch-graph-schema.sh")

    fakes = tmp_path / "fakes"
    (fakes / "msal").mkdir(parents=True)
    (fakes / "msal/__init__.py").write_text(FAKE_MSAL)
    (fakes / "requests").mkdir()
    (fakes / "requests/__init__.py").write_text(FAKE_REQUESTS)

    # Both the venv interpreter and any python3 on PATH are this interpreter,
    # so the script never reaches a system Python.
    venv_bin = root / ".venv/bin"
    venv_bin.mkdir(parents=True)
    shim = venv_bin / "python3"
    shim.write_text(f'#!/bin/sh\nexec "{sys.executable}" "$@"\n')
    shim.chmod(0o755)
    path_bin = tmp_path / "bin"
    path_bin.mkdir()
    (path_bin / "python3").symlink_to(shim)

    msal_log = tmp_path / "msal.log"
    requests_log = tmp_path / "requests.log"
    base_env = {
        "PATH": os.pathsep.join([str(path_bin), str(Path(jq).parent), "/usr/bin", "/bin"]),
        "HOME": str(tmp_path),
        "PYTHONPATH": str(fakes),
        "FAKE_MSAL_LOG": str(msal_log),
        "FAKE_REQUESTS_LOG": str(requests_log),
        "FAKE_MSAL_TOKEN": MSAL_TOKEN,
        "EXPECT_SECRET": CLIENT_SECRET,
    }

    def run(extra_env=None, env_file=None):
        if env_file is not None:
            (root / ".env").write_text(env_file)
        env = dict(base_env)
        env.update(extra_env or {})
        result = subprocess.run(
            [bash, str(root / "scripts/fetch-graph-schema.sh")],
            env=env,
            capture_output=True,
            text=True,
            timeout=60,
        )
        return {
            "code": result.returncode,
            "output": result.stdout + result.stderr,
            "msal": _read_log(msal_log),
            "graph": _read_log(requests_log),
            "schema": root / "cache/graph-schema.json",
        }

    return run


def _assert_schema_written(result):
    schema = json.loads(result["schema"].read_text())
    assert set(schema["settings"]) == {"softwareupdate_actions"}


def test_supplied_token_skips_msal_and_reaches_graph(sandbox):
    result = sandbox({"GRAPH_ACCESS_TOKEN": SUPPLIED_TOKEN})

    assert result["code"] == 0, result["output"]
    _assert_schema_written(result)
    assert result["msal"] == []  # MSAL was never imported
    assert [call["authorization"] for call in result["graph"]] == [f"Bearer {SUPPLIED_TOKEN}"]
    assert "pre-acquired Graph access token" in result["output"]
    assert SUPPLIED_TOKEN not in result["output"]


def test_supplied_token_is_not_inherited_by_children(sandbox):
    result = sandbox({"GRAPH_ACCESS_TOKEN": SUPPLIED_TOKEN})

    assert result["code"] == 0, result["output"]
    assert [call["graph_access_token_in_env"] for call in result["graph"]] == [False]


def test_supplied_token_wins_over_client_secret(sandbox):
    result = sandbox(
        {
            "GRAPH_ACCESS_TOKEN": SUPPLIED_TOKEN,
            "CLIENT_ID": CLIENT_ID,
            "CLIENT_SECRET": CLIENT_SECRET,
            "TENANT_ID": TENANT_ID,
        }
    )

    assert result["code"] == 0, result["output"]
    assert result["msal"] == []
    assert [call["authorization"] for call in result["graph"]] == [f"Bearer {SUPPLIED_TOKEN}"]
    assert "CLIENT_SECRET is also set; it is ignored" in result["output"]
    assert CLIENT_SECRET not in result["output"]


def test_client_secret_path_still_works(sandbox):
    result = sandbox(
        {"CLIENT_ID": CLIENT_ID, "CLIENT_SECRET": CLIENT_SECRET, "TENANT_ID": TENANT_ID}
    )

    assert result["code"] == 0, result["output"]
    _assert_schema_written(result)
    clients = [entry for entry in result["msal"] if entry["event"] == "client"]
    assert clients == [
        {
            "event": "client",
            "client_id": CLIENT_ID,
            "authority": f"https://login.microsoftonline.com/{TENANT_ID}",
            "secret_matches": True,
        }
    ]
    assert [call["authorization"] for call in result["graph"]] == [f"Bearer {MSAL_TOKEN}"]
    # Existing redaction: IDs masked to their first block, secret and token never shown.
    assert "Client ID: 11111111..." in result["output"]
    for value in (CLIENT_ID, TENANT_ID, CLIENT_SECRET, MSAL_TOKEN):
        assert value not in result["output"]


def test_token_in_env_file_is_ignored(sandbox):
    env_file = (
        f"CLIENT_ID={CLIENT_ID}\nCLIENT_SECRET={CLIENT_SECRET}\nTENANT_ID={TENANT_ID}\n"
        f"GRAPH_ACCESS_TOKEN={SUPPLIED_TOKEN}\n"
    )
    result = sandbox(env_file=env_file)

    assert result["code"] == 0, result["output"]
    assert [call["authorization"] for call in result["graph"]] == [f"Bearer {MSAL_TOKEN}"]
    assert [call["graph_access_token_in_env"] for call in result["graph"]] == [False]
    assert SUPPLIED_TOKEN not in result["output"]


@pytest.mark.parametrize(
    "bad_token",
    [
        f"Bearer {SUPPLIED_TOKEN}",
        "not-a-jwt-SYNTHETICVALUE",
        f"{SUPPLIED_TOKEN}\n",
        '{"access_token": "SYNTHETICVALUE"}',
    ],
)
def test_malformed_token_rejected_without_echo(sandbox, bad_token):
    result = sandbox({"GRAPH_ACCESS_TOKEN": bad_token})

    assert result["code"] == 1
    assert "GRAPH_ACCESS_TOKEN is set but is not a bare access token" in result["output"]
    assert result["graph"] == []
    assert result["msal"] == []
    assert "SYNTHETICVALUE" not in result["output"]
    assert SUPPLIED_TOKEN not in result["output"]


def test_graph_rejection_does_not_print_token(sandbox):
    result = sandbox({"GRAPH_ACCESS_TOKEN": SUPPLIED_TOKEN, "FAKE_GRAPH_STATUS": "401"})

    assert result["code"] == 1
    assert "Error fetching data: 401 Error" in result["output"]
    assert SUPPLIED_TOKEN not in result["output"]


def test_missing_credentials_lists_token_option(sandbox):
    result = sandbox()

    assert result["code"] == 1
    assert "Missing required credentials" in result["output"]
    assert "GRAPH_ACCESS_TOKEN" in result["output"]
    assert result["graph"] == []
