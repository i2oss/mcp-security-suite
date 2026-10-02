# What a Security Gate Caught: Hardening Two MCP Servers

**TL;DR** — I built one reusable, CI-gated security suite and pointed it at two of my own [MCP](https://modelcontextprotocol.io) servers. On the first it found a serious set of real bugs — arbitrary file **read and write**, a file-existence oracle, and a read→LLM→network exfiltration chain — all traced to a single unguarded function. I fixed every one, pinned each with a test, and wired the suite into CI so the hardening can't regress. The second server came back clean, and onboarding it made the suite itself better. Weeks later the gate caught a live CVE in a transitive dependency with no human in the loop. That last part is the point: the security isn't a one-time audit, it's a gate that keeps working.

---

## The setup

Two MCP servers, deliberately different surfaces:

- **`s1000d-mcp`** — tools that read and write S1000D XML files and send document content to an LLM. Surface: untrusted file paths, untrusted XML, untrusted document text.
- **`devtrack-mcp`** — tools that talk to a REST task-tracking API. Surface: input handling and error handling (no local files at all).

One suite gates both: repo scanners (bandit, pip-audit, gitleaks), a black-box protocol fuzz harness that drives any MCP server over stdio, and each server's own security tests. It runs on every PR and weekly, and branch protection means nothing merges to `main` while it's red.

## The headline: one function, four vulnerabilities

Every file-path tool in `s1000d-mcp` ran its paths through this:

```python
def _resolve(path_str: str) -> Path:
    path = Path(path_str)
    return path if path.is_absolute() else REPO_ROOT / path
```

Absolute paths pass straight through. Relative paths get joined to the repo root — but `../` walks right back out. Nothing confines the result. Six path parameters across five tools, all exposed. That one gap produced four distinct attack vectors:

| # | Vector | Proof |
|---|---|---|
| **V1** | **Arbitrary file read** | Four tools opened `/etc/hostname` and a planted secret via `../` escape |
| **V2** | **Arbitrary file write / overwrite** *(worst)* | `generate_data_module_skeleton` wrote outside the repo, and overwrote an existing file via absolute path — silent data destruction, with caller-controlled content |
| **V3** | **File-existence oracle** | The error text distinguished a present file ("XML is not well-formed…") from a missing one ("File not found…"), so an attacker could map which paths exist on the host *even with no content leak* |
| **V4** | **Exfiltration chain** | `suggest_fix` reads a file and sends it to an LLM API — so a model coaxed into `suggest_fix(dm_path="~/.ssh/id_rsa")` reads the key and ships it off-host |

**The fix** was a single choke point applied everywhere `_resolve` was used — resolve the path, then confirm it's still inside the allowed base directory, and reject it before anything is opened or written:

```python
resolved = (base / path_str).resolve()
if resolved != base and not resolved.is_relative_to(base):
    raise PathNotAllowed(...)
```

One helper neutralized the read, the write, the oracle, and the exfiltration chain at once. Each vector now has a test in `tests/security/` that asserts it fails with the boundary error.

## The other real issues

- **Unbounded memory (DoS).** Nothing hung or crashed — the two scary XML DoS classes (billion-laughs entity expansion and deep nesting) were already handled by libxml2's defaults. But there was *no size cap*: a 68 MB document cost ~436 MB of RAM (6–7×). A few large concurrent calls could OOM the process. Fixed with file-size and string-length caps checked before any parse. *(Lesson: the generic "500k-character payload" DoS test missed this entirely — the inputs are files, and 500k chars is nothing. The real lever was file size and concurrency.)*
- **Host-path leakage.** Almost every response echoed absolute paths like `/Users/<name>/...`, leaking username and directory layout. Fixed by returning repo-relative paths consistently.
- **One uncaught exception, found three times.** A malformed schema raised `XMLSyntaxError`, which the schema-load block didn't catch — so a caller got a raw error instead of the tool's clean structured contract. The same three-line gap surfaced independently in the XXE test, the traversal test, and the error-leakage sweep. One `except` clause closed all three.

And one thing that was **already right**: XXE. The lxml parser resolved no entities and made no network calls. I didn't take that on faith — I proved it with a positive control that *does* leak, then pinned the hardened parser settings explicitly so a future dependency bump can't silently re-enable XXE.

## Why the custom harness beat an off-the-shelf scan

I ran an existing MCP red-team scanner first. It scored the server **0/100** — and that number was almost useless in both directions. Most of its "critical" findings were false positives (command-injection flags on a server that never touches a shell), and it **missed the worst actual bug**: it only checks whether `/etc/passwd` *contents* come back, so it never saw V1–V4, because the tools returned a parse error, not the file.

That gap became the suite's defining feature. For every string parameter, the harness sends one path to a file that **exists** outside scope and one to a sibling that **doesn't**, and compares the replies. If they differ, the tool reached outside its directory — even when nothing leaked. It also strips echoed input before judging leaks, so a tool that merely reflects its argument isn't misread as vulnerable. **A scanner score is a starting point, not a verdict** — the real work was the differential probe and verifying every finding by hand.

## The second server, and making the suite honest

`devtrack-mcp` scanned **100/100, clean** — typed (pydantic) parameters, integer IDs, every tool catching its API error and returning a structured result, and no token ever leaking into a response. (It was scanned against a dead local endpoint, so no real API traffic and no tasks touched.) A genuinely well-built server *should* come back clean, and this one did.

But onboarding a second, differently-shaped server exposed two bugs in **the suite itself**:

1. A **false positive** on `Optional`/union tool parameters — the harness treated any parameter with no top-level JSON `type` as a string and fuzzed list/object params, whose validation errors echoed the input and tripped the differential probe. Fixed to fuzz only genuine string (or nullable-string) params.
2. A hidden **`uv.lock` requirement** in the CI caching that failed any repo without a committed lockfile. Fixed to cache on `pyproject.toml` instead.

Both fixes shipped in the suite's `v1` tag, so every repo got them on the next run. Finding them is exactly what a second real target is for.

## The gate earning its keep

Here's the part I like most. Months after the servers were hardened, a routine run flagged a **HIGH**: `pyjwt 2.14.0`, advisory **PYSEC-2026-4141**, pulled in transitively through the MCP SDK. Nobody went looking for it — a dependency I don't import directly got a fresh CVE, and the weekly scheduled scan turned the gate red on its own. Bumped to `2.15.1`, gate green again. That's the difference between a security *audit* (true on the day you run it) and a security *gate* (stays true, or stops the build).

## Outcome

Both servers are hardened, each finding pinned by a test, both gated in CI with branch protection and a weekly drift check — and now observable, with an OpenTelemetry span per tool call and token/cost tracking on the LLM-backed tool. The controls map to the **OWASP Top 10 for LLM Applications (2025)** and the **OWASP MCP Security Cheat Sheet**. One reusable suite did it, and it keeps doing it.

**Repos:** [`mcp-security-suite`](https://github.com/i2oss/mcp-security-suite) · [`s1000d-mcp`](https://github.com/i2oss/s1000d-mcp) · [`devtrack-mcp`](https://github.com/i2oss/devtrack-mcp)
