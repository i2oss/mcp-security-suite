"""Per-project configuration.

A project drops an `mcp-security.toml` at its repo root telling the suite how
to start its server and how to interpret results. Example:

    [server]
    command = "python"
    args = ["-m", "my_server"]
    # env = { MY_FLAG = "1" }
    timeout = 8.0

    [scan]
    skip_tools = ["ping"]

    # Give a tool valid values for required non-string params so probes reach
    # the real code path instead of failing argument validation first.
    [scan.tool_arg_overrides.generate_data_module_skeleton]
    tech_name = "APU"
    info_name = "Remove"
    dmc = { modelIdentCode = "MERM100", systemCode = "049" }  # ...

    # Accept a known, reviewed behaviour so CI doesn't fail on it. Each waiver
    # needs a reason; waived findings are reported but excluded from the score
    # and the pass/fail gate.
    [[waivers]]
    category = "output-injection"
    reason = "Tools echo the caller-supplied path in status fields; low risk, accepted."
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .report import Finding, ScanResult


@dataclass
class Waiver:
    category: str
    reason: str
    tool: str | None = None          # None = applies to every tool
    finding_id: str | None = None    # or waive one specific finding id

    def matches(self, f: Finding) -> bool:
        if self.finding_id:
            return f.id == self.finding_id
        return f.category == self.category and (self.tool in (None, f.tool))


@dataclass
class Config:
    command: str
    args: list[str] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)
    timeout: float = 8.0
    skip_tools: list[str] = field(default_factory=list)
    tool_arg_overrides: dict[str, dict[str, Any]] = field(default_factory=dict)
    extra_payloads: list[str] = field(default_factory=list)
    waivers: list[Waiver] = field(default_factory=list)
    fail_on: str = "high"            # gate: fail if any finding at/above this

    def scanner_config(self) -> dict[str, Any]:
        return {
            "timeout": self.timeout,
            "skip_tools": self.skip_tools,
            "tool_arg_overrides": self.tool_arg_overrides,
            "extra_payloads": self.extra_payloads,
        }

    @classmethod
    def from_file(cls, path: str | Path) -> "Config":
        data = tomllib.loads(Path(path).read_text())
        return cls.from_dict(data)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Config":
        server = data.get("server", {})
        scan = data.get("scan", {})
        if "command" not in server:
            raise ValueError("config: [server] command is required")
        waivers = [
            Waiver(
                category=w.get("category", ""),
                reason=w.get("reason", ""),
                tool=w.get("tool"),
                finding_id=w.get("finding_id"),
            )
            for w in data.get("waivers", [])
        ]
        for w in waivers:
            if not w.reason:
                raise ValueError(
                    f"config: waiver for {w.category or w.finding_id!r} needs a reason"
                )
        return cls(
            command=server["command"],
            args=list(server.get("args", [])),
            env={str(k): str(v) for k, v in server.get("env", {}).items()},
            timeout=float(server.get("timeout", 8.0)),
            skip_tools=list(scan.get("skip_tools", [])),
            tool_arg_overrides=dict(scan.get("tool_arg_overrides", {})),
            extra_payloads=list(scan.get("extra_payloads", [])),
            waivers=waivers,
            fail_on=str(data.get("gate", {}).get("fail_on", "high")),
        )


def apply_waivers(result: ScanResult, waivers: list[Waiver]) -> tuple[ScanResult, list[Finding]]:
    """Split a result's findings into active (kept, scored) and waived
    (reported, not scored). Returns (active_result, waived_findings)."""
    active, waived = [], []
    for f in result.findings:
        if any(w.matches(f) for w in waivers):
            waived.append(f)
        else:
            active.append(f)
    result.findings = active
    return result, waived
