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
directly. (`--no-layer1` runs only the protocol harness; `--repo` points the
scanners at a repo root other than the current directory.)

## Use it in CI (GitHub Actions)

The scanner is published as a **reusable workflow**, so a target repo adopts the
gate in a few lines. Add `.github/workflows/security.yml` to the server's repo:

```yaml
name: Security
on:
  push: { branches: [main] }
  pull_request: { branches: [main] }
  schedule:
    - cron: "0 6 * * 1"   # weekly — catches dependency drift (new CVEs)

jobs:
  scan:
    uses: i2oss/mcp-security-suite/.github/workflows/scan.yml@v1
    with:
      config: mcp-security.toml

  # Optional layer 3: the server's own security tests (see below).
  security-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: astral-sh/setup-uv@v3
        with: { enable-cache: true }
      - run: uv python install 3.11
      - run: uv sync --all-extras --dev
      - run: uv run pytest tests/security/ -v
```

Then make it a **gate**: in the repo's branch-protection rule for `main`,
require the `scan / scan` check (and `security-tests` if used) and disallow
bypass — including for admins. Now no PR merges into `main` unless the scan is
clean, and the weekly `schedule` re-runs it so a newly disclosed CVE in a
dependency turns the gate red on its own.

The reusable workflow installs the target server with `uv sync` by default
(override with the `install-command` input) and needs no `uv.lock` committed —
it caches on `pyproject.toml`.

### The three layers

- **Layers 1 & 2** are generic and live here — a repo gets them for free by
  calling the workflow above.
- **Layer 3** is per-project: the server's own `tests/security/` pinning
  behaviour the black-box harness can't reach (e.g. an XXE positive-control, or
  that an API token never appears in a tool's response). The suite doesn't ship
  these — each server writes its own and runs them in the `security-tests` job.

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

## Versioning

Callers pin the reusable workflow with `@v1`. **`v1` is a moving major tag**: it
always points at the latest backward-compatible release of the 1.x line, so a
fix to the scanner reaches every repo on the next run with no change on their
side. Releasing a caller-visible fix:

```bash
git tag -f v1 && git push -f origin v1
```

Breaking changes to the config schema or the workflow inputs would ship as a new
major tag (`v2`); callers upgrade by bumping `@v1` → `@v2` when they're ready.

## Proven on real servers

The gate runs in production on two MCP servers:
[`s1000d-mcp`](https://github.com/i2oss/s1000d-mcp) (file-handling tools —
traversal, XXE, DoS, LLM-injection surface) and
[`devtrack-mcp`](https://github.com/i2oss/devtrack-mcp) (REST-API tools — error
handling and token-leak surface). Onboarding the second server also hardened the
suite itself: it surfaced a false positive on union/`Optional` tool parameters
and a hidden `uv.lock` requirement, both fixed in `v1`.

## License

MIT
