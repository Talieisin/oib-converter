"""Exercise the schema fetcher's retry path with synthetic Graph responses."""

import json
import random
import time
from pathlib import Path

import requests

SCRIPT = Path(__file__).parents[1] / "scripts/fetch-graph-schema.sh"
DEFINITION = {"id": "softwareupdate_actions", "applicability": {"platform": "macOS"}}


class Response:
    def __init__(self, status_code, headers=None, payload=None):
        self.status_code = status_code
        self.headers = headers or {}
        self.payload = payload

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.exceptions.HTTPError(f"{self.status_code} Error", response=self)

    def json(self):
        return self.payload


def ok():
    return Response(200, payload={"value": [DEFINITION]})


def run_fetcher(monkeypatch, outcomes):
    """Run the embedded Python against queued responses or exceptions.

    Returns (namespace, calls, sleeps, exit_code); exit_code is None on success.
    """
    queue = list(outcomes)
    calls = []
    sleeps = []

    def fake_get(url, **kwargs):
        calls.append(url)
        outcome = queue.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    monkeypatch.setattr(requests, "get", fake_get)
    monkeypatch.setattr(time, "sleep", sleeps.append)
    monkeypatch.setattr(random, "uniform", lambda low, high: 0.0)
    monkeypatch.setenv("GRAPH_URL", "https://graph.example.test/settings")
    monkeypatch.setenv("ACCESS_TOKEN", "synthetic-test-token")
    python_source = (
        SCRIPT.read_text().split("> \"$OUTPUT_FILE\" <<'EOF'\n", 1)[1].split("\nEOF\n", 1)[0]
    )
    namespace = {}
    exit_code = None
    try:
        exec(compile(python_source, str(SCRIPT), "exec"), namespace)
    except SystemExit as e:
        exit_code = e.code
    return namespace, calls, sleeps, exit_code


def test_retries_gateway_timeout_and_honours_retry_after(monkeypatch, capsys):
    _, calls, sleeps, exit_code = run_fetcher(
        monkeypatch,
        [
            Response(504),
            Response(429, headers={"Retry-After": "7"}),
            requests.exceptions.ConnectionError("connection reset"),
            ok(),
        ],
    )

    assert exit_code is None
    assert len(calls) == 4
    # Exponential backoff for the 504 and the dropped connection; Retry-After for the 429.
    assert sleeps == [2.0, 7.0, 8.0]
    output = json.loads(capsys.readouterr().out)
    assert set(output["settings"]) == {"softwareupdate_actions"}


def test_gives_up_after_five_retries(monkeypatch, capsys):
    _, calls, sleeps, exit_code = run_fetcher(monkeypatch, [Response(503)] * 6)

    assert exit_code == 1
    assert len(calls) == 6
    assert sleeps == [2.0, 4.0, 8.0, 16.0, 32.0]
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "retry 5/5" in captured.err
    assert "Error fetching data: 503 Error" in captured.err


def test_does_not_retry_client_errors(monkeypatch, capsys):
    _, calls, sleeps, exit_code = run_fetcher(monkeypatch, [Response(403), ok()])

    assert exit_code == 1
    assert len(calls) == 1
    assert sleeps == []
    assert "Error fetching data: 403 Error" in capsys.readouterr().err


def test_backoff_cap_jitter_and_retry_after_parsing(monkeypatch, capsys):
    namespace, *_ = run_fetcher(monkeypatch, [ok()])
    capsys.readouterr()
    monkeypatch.setattr(random, "uniform", lambda low, high: high)

    backoff_delay = namespace["backoff_delay"]
    assert backoff_delay(1) == 3.0  # 2s plus up to half again of jitter
    assert backoff_delay(10) == 90.0  # backoff capped at 60s before jitter

    parse_retry_after = namespace["parse_retry_after"]
    assert parse_retry_after("12") == 12.0
    assert parse_retry_after("-3") == 0.0
    assert parse_retry_after("86400") == 300.0
    assert parse_retry_after("Wed, 21 Oct 2015 07:28:00 GMT") == 0.0
    assert parse_retry_after("soon") is None
    assert parse_retry_after("NaN") is None
    assert parse_retry_after("inf") == 300.0
    assert parse_retry_after(None) is None


def test_nan_retry_after_falls_back_to_backoff(monkeypatch, capsys):
    _, calls, sleeps, exit_code = run_fetcher(
        monkeypatch, [Response(429, headers={"Retry-After": "NaN"}), ok()]
    )

    assert exit_code is None
    assert len(calls) == 2
    assert sleeps == [2.0]
