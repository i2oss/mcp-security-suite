"""Layer 1: generic scanners for any Python repo.

Thin wrappers over three standard tools, normalised into the suite's Finding
model so layer-1 and layer-2 results render and gate together:
  - bandit    : Python source security linter (AST-based)
  - pip-audit : known-vuln check on installed/declared dependencies
  - gitleaks  : committed-secret scanner

A scanner that isn't installed is reported as an `info` finding ("not run"),
never a crash -- so the suite degrades gracefully in a minimal environment
and CI can decide whether a missing scanner should fail the build.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

from .report import Finding

_SEV = {  # bandit severities -> ours
    "HIGH": "high", "MEDIUM": "medium", "LOW": "low", "UNDEFINED": "info",
}


def _missing(tool: str, install: str) -> Finding:
    return Finding(
        id=f"L1-{tool}", severity="info", category="scanner-missing", tool=None,
        title=f"{tool} not run (not installed)",
        detail=f"The {tool} scanner was not found on PATH, so its checks were "
               "skipped.",
        remediation=f"Install it to enable this layer: {install}")


_BANDIT_EXCLUDE = ".venv,venv,.git,node_modules,build,dist,.tox,.eggs"


def run_bandit(repo: Path) -> list[Finding]:
    if not shutil.which("bandit"):
        return [_missing("bandit", "pip install bandit")]
    # Scan the project's own source only -- never the virtualenv or vendored
    # code, which would drown real findings in thousands of dependency hits.
    target = str(repo / "src") if (repo / "src").is_dir() else str(repo)
    proc = subprocess.run(
        ["bandit", "-r", "-f", "json", "-q", "-x", _BANDIT_EXCLUDE, target],
        capture_output=True, text=True)
    try:
        data = json.loads(proc.stdout or "{}")
    except json.JSONDecodeError:
        return [Finding(id="L1-bandit-err", severity="info",
                        category="scanner-error", tool=None,
                        title="bandit produced no parseable output",
                        detail=(proc.stderr or "")[:200])]
    out = []
    for r in data.get("results", []):
        out.append(Finding(
            id=f"BANDIT-{r.get('test_id','?')}",
            severity=_SEV.get(r.get("issue_severity", "UNDEFINED"), "low"),
            category="static-analysis", tool=None,
            title=f"bandit {r.get('test_id')}: {r.get('test_name')}",
            detail=r.get("issue_text", ""),
            evidence=f"{r.get('filename')}:{r.get('line_number')}",
            remediation="Review the flagged code; see the bandit test docs."))
    return out


def run_pip_audit(repo: Path) -> list[Finding]:
    if not shutil.which("pip-audit"):
        return [_missing("pip-audit", "pip install pip-audit")]
    proc = subprocess.run(
        ["pip-audit", "-f", "json", "--progress-spinner", "off"],
        capture_output=True, text=True, cwd=str(repo))
    try:
        data = json.loads(proc.stdout or "{}")
    except json.JSONDecodeError:
        return [Finding(id="L1-pipaudit-err", severity="info",
                        category="scanner-error", tool=None,
                        title="pip-audit produced no parseable output",
                        detail=(proc.stderr or "")[:200])]
    deps = data.get("dependencies", data) if isinstance(data, dict) else data
    out = []
    for dep in deps:
        for v in dep.get("vulns", []) or []:
            out.append(Finding(
                id=f"PIPAUDIT-{v.get('id','?')}", severity="high",
                category="dependency", tool=None,
                title=f"Vulnerable dependency: {dep.get('name')} "
                      f"{dep.get('version')}",
                detail=v.get("description", "")[:300],
                evidence=v.get("id", ""),
                remediation="Upgrade to a fixed version: "
                            f"{', '.join(v.get('fix_versions', []) or ['see advisory'])}."))
    return out


def run_gitleaks(repo: Path) -> list[Finding]:
    if not shutil.which("gitleaks"):
        return [_missing("gitleaks", "https://github.com/gitleaks/gitleaks")]
    report = repo / ".gitleaks-report.json"
    subprocess.run(
        ["gitleaks", "detect", "--no-banner", "--report-format", "json",
         "--report-path", str(report), "--source", str(repo)],
        capture_output=True, text=True)
    if not report.exists():
        return []
    try:
        leaks = json.loads(report.read_text() or "[]")
    finally:
        report.unlink(missing_ok=True)
    return [Finding(
        id=f"GITLEAKS-{i}", severity="critical", category="secret", tool=None,
        title=f"Committed secret: {leak.get('RuleID','?')}",
        detail=f"A secret matching '{leak.get('RuleID')}' is committed in the "
               "repository history.",
        evidence=f"{leak.get('File')}:{leak.get('StartLine')}",
        remediation="Remove the secret, rotate it, and purge it from history.")
        for i, leak in enumerate(leaks)]


def run_layer1(repo: str | Path) -> list[Finding]:
    repo = Path(repo)
    findings = [*run_bandit(repo), *run_pip_audit(repo), *run_gitleaks(repo)]
    # A vuln can be reported once per dependency that pulls it in; collapse to
    # one finding per id.
    seen: set[str] = set()
    out = []
    for f in findings:
        if f.id in seen:
            continue
        seen.add(f.id)
        out.append(f)
    return out
