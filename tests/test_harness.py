"""Self-tests for the harness: it must catch the deliberately vulnerable demo
server and give the hardened one a clean bill of health. These are the tests
that keep the suite itself honest.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from mcp_security_suite.config import Config, apply_waivers
from mcp_security_suite.harness import _string_params, run_scan
from mcp_security_suite.report import Finding, ScanResult

DEMO = Path(__file__).resolve().parents[1] / "demo"
PY = sys.executable


def _scan(server: str) -> ScanResult:
    return run_scan(PY, [str(DEMO / server)], config={"timeout": 6})


def test_catches_vulnerable_server():
    r = _scan("vulnerable_server.py")
    cats = {f.category for f in r.findings}
    # The headline flaw must be caught as critical.
    assert any(f.severity == "critical" and f.category == "path-traversal"
               for f in r.findings), "arbitrary file read not detected"
    # And the other planted flaws surface too.
    assert "output-injection" in cats
    assert "error-leakage" in cats
    assert r.score() < 50


def test_safe_server_is_clean():
    r = _scan("safe_server.py")
    assert r.findings == [], f"unexpected findings: {[f.title for f in r.findings]}"
    assert r.score() == 100


def test_discovers_all_tools():
    r = _scan("safe_server.py")
    assert set(r.tools) == {
        "read_file", "stat_file", "echo", "parse_size", "crash_on_error"
    }


def test_waiver_excludes_a_category_from_the_score():
    r = _scan("vulnerable_server.py")
    from mcp_security_suite.config import Waiver
    waivers = [Waiver(category="output-injection", reason="accepted for test")]
    before = len(r.findings)
    _, waived = apply_waivers(r, waivers)
    assert waived, "waiver matched nothing"
    assert all(f.category != "output-injection" for f in r.findings)
    assert len(r.findings) + len(waived) == before


def test_config_requires_a_reason_for_waivers():
    with pytest.raises(ValueError):
        Config.from_dict({
            "server": {"command": "python"},
            "waivers": [{"category": "dos"}],  # no reason
        })


def test_only_genuine_string_params_are_fuzzed():
    # A string payload belongs only in string (or nullable-string) params.
    # Feeding one to a list/object/int param just triggers the server's own
    # argument validation, whose error echoes the input and used to look like
    # a finding (regression from onboarding a pydantic-typed server).
    schema = {
        "properties": {
            "keyword": {"type": "string"},
            "opt_keyword": {"anyOf": [{"type": "string"}, {"type": "null"}]},
            "project_id": {"type": "integer"},
            "field_ids": {"anyOf": [{"type": "array"}, {"type": "null"}]},
            "field_values": {"anyOf": [{"type": "array"}, {"type": "null"}]},
            "condition": {"anyOf": [{"type": "object"}, {"type": "null"}]},
            "flag": {"type": "boolean"},
        }
    }
    assert _string_params(schema) == ["keyword", "opt_keyword"]


def test_config_roundtrips_server_and_gate():
    cfg = Config.from_dict({
        "server": {"command": "python", "args": ["-m", "x"], "timeout": 5},
        "scan": {"skip_tools": ["ping"]},
        "gate": {"fail_on": "medium"},
    })
    assert cfg.command == "python"
    assert cfg.args == ["-m", "x"]
    assert cfg.skip_tools == ["ping"]
    assert cfg.fail_on == "medium"
