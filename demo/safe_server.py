"""A hardened counterpart to vulnerable_server.py. The harness must report
this one as clean -- it exercises the same tool shapes with the fixes
applied, so it doubles as the harness's negative control.
"""

from __future__ import annotations

import os
from pathlib import Path

from mcp.server.mcpserver import MCPServer

mcp = MCPServer(name="safe-demo", version="0.0.0",
                instructions="Hardened demo server for harness tests.")

BASE_DIR = Path(os.environ.get("SAFE_DEMO_BASE", os.getcwd())).resolve()
MAX_LEN = 100_000


class _Refused(ValueError):
    pass


def _safe_path(path_str: str) -> Path:
    p = (BASE_DIR / path_str).resolve()
    if p != BASE_DIR and BASE_DIR not in p.parents:
        raise _Refused("path is outside the allowed directory")
    return p


@mcp.tool()
def read_file(path: str) -> dict:
    """Read a file inside the allowed directory."""
    try:
        p = _safe_path(path)
    except _Refused as exc:
        return {"ok": False, "error": str(exc)}
    if not p.is_file():
        # Uniform reply for missing/blocked so no existence oracle exists.
        return {"ok": False, "error": "not available"}
    if p.stat().st_size > MAX_LEN:
        return {"ok": False, "error": "file too large"}
    return {"ok": True, "content": p.read_text(encoding="utf-8", errors="replace")}


@mcp.tool()
def stat_file(path: str) -> dict:
    """Report readability without revealing existence of out-of-scope paths."""
    try:
        p = _safe_path(path)
    except _Refused as exc:
        return {"ok": False, "error": str(exc)}
    return {"ok": True, "readable": p.is_file()}


@mcp.tool()
def echo(message: str) -> dict:
    """Echo a length-capped message back as structured data."""
    if len(message) > MAX_LEN:
        return {"ok": False, "error": "message too long"}
    return {"ok": True, "length": len(message)}


@mcp.tool()
def parse_size(text: str) -> dict:
    """Return the length of the text, with a size cap."""
    if len(text) > MAX_LEN:
        return {"ok": False, "error": "input too long"}
    return {"ok": True, "length": len(text)}


@mcp.tool()
def crash_on_error(path: str) -> dict:
    """Read and upper-case a file, returning a generic error on failure."""
    try:
        p = _safe_path(path)
    except _Refused as exc:
        return {"ok": False, "error": str(exc)}
    if not p.is_file():
        return {"ok": False, "error": "not available"}
    return {"ok": True, "content": p.read_text(errors="replace").upper()}


def main() -> None:
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
