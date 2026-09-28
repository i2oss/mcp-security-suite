"""A deliberately VULNERABLE MCP server, used only to prove the security
harness catches real problems. Do not copy these patterns into real code --
every tool here reproduces a common MCP flaw on purpose.

Flaws planted (each is what the harness must detect):
  - read_file: path traversal, returns file contents (arbitrary read)
  - stat_file: existence oracle (distinct replies for present vs missing)
  - echo: reflects input verbatim (output-injection channel)
  - parse_size: no input-size limit (unbounded work)
  - crash_on_error: leaks a stack trace / internal path on bad input
Run over stdio like any MCP server:  python demo/vulnerable_server.py
"""

from __future__ import annotations

import os
import traceback

from mcp.server.mcpserver import MCPServer

mcp = MCPServer(name="vulnerable-demo", version="0.0.0",
                instructions="Deliberately insecure demo server for harness tests.")


@mcp.tool()
def read_file(path: str) -> str:
    """Read a file and return its contents."""
    # VULN: no path confinement -- absolute paths and ../ escape freely.
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        return fh.read()


@mcp.tool()
def stat_file(path: str) -> str:
    """Report whether a file exists."""
    # VULN: existence oracle -- the reply distinguishes present from missing,
    # so a caller can probe the host filesystem.
    if os.path.exists(path):
        return f"{path} exists ({os.path.getsize(path)} bytes)"
    return f"{path}: no such file"


@mcp.tool()
def echo(message: str) -> str:
    """Echo a message back."""
    # VULN: reflects caller input verbatim into output (injection channel).
    return f"you said: {message}"


@mcp.tool()
def parse_size(text: str) -> dict:
    """Return the length of the text."""
    # VULN: no size cap -- accepts arbitrarily large input.
    return {"length": len(text), "upper_sample": text[:10].upper()}


@mcp.tool()
def crash_on_error(path: str) -> str:
    """Read and upper-case a file."""
    # VULN: on error, returns the raw traceback (absolute paths, internals).
    try:
        with open(path) as fh:
            return fh.read().upper()
    except Exception:
        return traceback.format_exc()


def main() -> None:
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
