"""Finding model and report rendering (markdown + JSON)."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from typing import Any

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_DEDUCTION = {"critical": 25, "high": 10, "medium": 5, "low": 2, "info": 0}


@dataclass
class Finding:
    id: str
    severity: str          # critical | high | medium | low | info
    category: str          # e.g. path-traversal, error-leakage
    tool: str | None
    title: str
    detail: str
    evidence: str = ""
    remediation: str = ""


@dataclass
class ScanResult:
    target: str
    tools: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)

    def score(self) -> int:
        return max(0, 100 - sum(_DEDUCTION[f.severity] for f in self.findings))

    def counts(self) -> dict[str, int]:
        c = {k: 0 for k in SEVERITY_ORDER}
        for f in self.findings:
            c[f.severity] += 1
        return c

    def worst(self) -> str | None:
        """Highest severity present, or None when there are no findings."""
        if not self.findings:
            return None
        return min((f.severity for f in self.findings), key=lambda s: SEVERITY_ORDER[s])

    def sorted_findings(self) -> list[Finding]:
        return sorted(self.findings, key=lambda f: SEVERITY_ORDER[f.severity])

    def to_json(self) -> str:
        return json.dumps(
            {
                "target": self.target,
                "score": self.score(),
                "counts": self.counts(),
                "tools": self.tools,
                "findings": [asdict(f) for f in self.sorted_findings()],
            },
            indent=2,
        )

    def to_markdown(self) -> str:
        c = self.counts()
        lines = [
            f"# MCP security scan: {self.target}",
            "",
            f"**Score:** {self.score()}/100  ",
            f"**Findings:** {c['critical']} critical, {c['high']} high, "
            f"{c['medium']} medium, {c['low']} low  ",
            f"**Tools scanned:** {', '.join(self.tools) or '(none)'}",
            "",
        ]
        if not self.findings:
            lines.append("No findings. Every probe was handled safely.")
            return "\n".join(lines)
        for f in self.sorted_findings():
            lines += [
                f"## [{f.severity.upper()}] {f.title}",
                f"- **category:** {f.category}"
                + (f" · **tool:** `{f.tool}`" if f.tool else ""),
                f"- {f.detail}",
            ]
            if f.evidence:
                lines.append(f"- evidence: `{f.evidence[:200].strip()}`")
            if f.remediation:
                lines.append(f"- fix: {f.remediation}")
            lines.append("")
        return "\n".join(lines)
