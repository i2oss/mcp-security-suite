"""Command-line entry point.

    mcp-security-suite scan --config mcp-security.toml [--repo .] [--json out.json]

Runs layer 1 (repo scanners) and layer 2 (MCP protocol fuzzing) together,
prints a report, and exits non-zero when an un-waived finding is at or above
the configured gate severity -- so it can gate a CI job directly.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .config import Config, apply_waivers
from .harness import run_scan
from .layer1 import run_layer1
from .report import SEVERITY_ORDER, ScanResult


def _gate_fails(result: ScanResult, fail_on: str) -> bool:
    threshold = SEVERITY_ORDER[fail_on]
    return any(SEVERITY_ORDER[f.severity] <= threshold for f in result.findings)


def scan_command(args: argparse.Namespace) -> int:
    cfg = Config.from_file(args.config)
    repo = Path(args.repo).resolve()

    result = run_scan(cfg.command, cfg.args, cfg.scanner_config(), cfg.env)
    if not args.no_layer1:
        result.findings.extend(run_layer1(repo))

    result, waived = apply_waivers(result, cfg.waivers)

    print(result.to_markdown())
    if waived:
        print(f"\n---\n### Waived ({len(waived)}) — reported, not gated")
        for f in waived:
            reason = next((w.reason for w in cfg.waivers if w.matches(f)), "")
            print(f"- [{f.severity}] {f.category} `{f.tool or ''}`: {reason}")

    if args.json:
        Path(args.json).write_text(result.to_json())
        print(f"\nJSON written to {args.json}")

    if _gate_fails(result, cfg.fail_on):
        print(f"\nGATE: FAIL — an un-waived finding is at or above "
              f"'{cfg.fail_on}'.", file=sys.stderr)
        return 1
    print(f"\nGATE: PASS — no un-waived finding at or above '{cfg.fail_on}'.")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="mcp-security-suite")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("scan", help="scan an MCP server and its repo")
    p.add_argument("--config", default="mcp-security.toml",
                   help="path to mcp-security.toml (default: ./mcp-security.toml)")
    p.add_argument("--repo", default=".", help="repo root for layer-1 scanners")
    p.add_argument("--json", help="also write the JSON report to this path")
    p.add_argument("--no-layer1", action="store_true",
                   help="skip the repo scanners; run only the protocol harness")
    p.set_defaults(func=scan_command)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
