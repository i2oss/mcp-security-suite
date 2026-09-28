# mcp-security-suite

A reusable, CI-gated security suite for [MCP](https://modelcontextprotocol.io) servers. Point it at any MCP server and it runs two layers of checks and fails the build on un-waived issues.

- **Layer 1 — repo scanners** (any Python repo): [bandit](https://bandit.readthedocs.io) (source), [pip-audit](https://pypi.org/project/pip-audit/) (dependencies), [gitleaks](https://github.com/gitleaks/gitleaks) (committed secrets).
- **Layer 2 — MCP protocol fuzz harness** (any MCP server, any language): starts the server over stdio, discovers its tools via `tools/list`, and fuzzes every string parameter for path traversal, oversized input, output-injection, and error leakage.

It is black-box: the harness talks the protocol, so it works against a server written in any language, not just Python.

## Why layer 2 is different from an ordinary scanner

Most scanners only flag a file read if the file's **contents** come back. But an MCP tool can open a file outside its scope and still return a parse error instead of the contents — the escape happened, you just can't see it. This harness sends, for every string parameter, one path to a file that **exists** outside scope and one to a sibling that **doesn't**, and compares the replies. If they differ, the tool is reaching outside its directory even when nothing leaks. It also strips echoed input before judging leaks and DoS, so a tool that merely reflects its input isn't misread as vulnerable.

## Install

```bash
pip install -e .            # the suite + the mcp client
pip install -e '.[scanners]'  # + bandit and pip-audit for layer 1
# gitleaks is a separate binary: https://github.com/gitleaks/gitleaks
```

## Use

Drop an `mcp-security.toml` in the target repo (see `examples/`), then:

```bash
mcp-security-suite scan --config mcp-security.toml --repo .
```

It prints a report, writes JSON with `--json out.json`, and **exits non-zero**
when an un-waived finding is at or above the gate severity — so it gates CI
directly.

## Config

```toml
[server]
command = "my-server"        # how to start the MCP server (stdio)
args = []
timeout = 8.0

[scan]
skip_tools = ["ping"]        # tools to leave out

# Give a tool valid values for required non-string params so probes reach the
# real code path instead of failing argument validation first.
[scan.tool_arg_overrides.some_tool]
required_object = { key = "value" }

[gate]
fail_on = "high"             # fail on any un-waived finding at/above this

# Accept a reviewed behaviour so it's reported but doesn't fail the build.
# A reason is required.
[[waivers]]
category = "output-injection"
reason = "Tools echo the caller's own input path; low risk, accepted 2026-09."
```

## What it checks (layer 2)

| Category | Detection |
|---|---|
| `path-traversal` | canary-content leak (confirmed read) **and** the exists/missing differential (out-of-scope reach even with no leak) |
| `dos` | hang on a 200k-char input, or processing it with no size limit (echoes excluded) |
| `output-injection` | caller input reflected verbatim into a response the model reads |
| `error-leakage` | stack traces, absolute host paths, or secret-shaped strings in responses |

## Trust the tool: it tests itself

`demo/vulnerable_server.py` plants each flaw on purpose and `demo/safe_server.py`
fixes them. `tests/` asserts the harness catches the first (critical) and gives
the second a clean 100/100 — so a change that weakens detection fails CI.

```bash
pytest
```

## License

MIT
