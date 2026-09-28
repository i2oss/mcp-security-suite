"""Layer 2: the MCP protocol fuzz harness.

Connects to a target MCP server over stdio, discovers its tools via
tools/list, and probes every string parameter with the payload library.
It is black-box: it works against any MCP server regardless of the
language it is written in.

The detection that the baseline scanner (mcp-red-team) missed is the
differential existence probe: a tool can open a file outside its scope and
still not return the contents (it returns a parse error instead). So for
every path-like parameter the harness sends one payload pointing at a file
that EXISTS outside scope and one pointing at a sibling that does NOT, and
compares the replies. If they differ, the tool is reaching outside its
directory even though the contents never come back.
"""

from __future__ import annotations

import asyncio
import json
import os
import tempfile
import uuid
from pathlib import Path
from typing import Any

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from . import payloads as P
from .report import Finding, ScanResult

DEFAULT_TIMEOUT = 8.0


def _tool_schema(tool: Any) -> dict[str, Any]:
    """Read a tool's input schema across MCP SDK versions (the Python model
    field is `input_schema`; older/other bindings use `inputSchema`)."""
    return getattr(tool, "input_schema", None) or getattr(tool, "inputSchema", None) or {}


def _string_params(schema: dict[str, Any]) -> list[str]:
    props = (schema or {}).get("properties", {}) or {}
    out = []
    for name, spec in props.items():
        t = spec.get("type")
        if t in (None, "string"):
            out.append(name)
    return out


def _default_for(spec: dict[str, Any]) -> Any:
    t = spec.get("type")
    return {"number": 0, "integer": 0, "boolean": False,
            "array": [], "object": {}}.get(t, "probe")


def _build_args(schema: dict[str, Any], param: str, value: str,
                overrides: dict[str, Any]) -> dict[str, Any]:
    props = (schema or {}).get("properties", {}) or {}
    args: dict[str, Any] = {}
    for name, spec in props.items():
        if name == param:
            args[name] = value
        elif name in overrides:
            args[name] = overrides[name]
        else:
            args[name] = _default_for(spec)
    return args


def _strip_echo(text: str, payload: str) -> str:
    """Remove reflections of the payload (raw and JSON-escaped) before we
    look for leaked content, so a plain echo isn't mistaken for a read."""
    escaped = json.dumps(payload)[1:-1]
    return text.replace(payload, " ").replace(escaped, " ")


class _Probe:
    def __init__(self, session: ClientSession, timeout: float):
        self.session = session
        self.timeout = timeout

    async def call(self, tool: str, args: dict[str, Any]):
        """Return (text, is_error, timed_out). Never raises."""
        try:
            result = await asyncio.wait_for(
                self.session.call_tool(tool, args), timeout=self.timeout
            )
        except asyncio.TimeoutError:
            return "", True, True
        except Exception as exc:  # protocol/validation error from the server
            return f"{type(exc).__name__}: {exc}", True, False
        parts = []
        for block in getattr(result, "content", []) or []:
            parts.append(getattr(block, "text", "") or "")
        text = " ".join(parts) or json.dumps(
            getattr(result, "structuredContent", None) or {}
        )
        return text, bool(getattr(result, "isError", False)), False


class Scanner:
    def __init__(self, config: dict[str, Any] | None = None):
        self.config = config or {}
        self.skip = set(self.config.get("skip_tools", []))
        self.arg_overrides = self.config.get("tool_arg_overrides", {})
        self.extra_payloads = list(self.config.get("extra_payloads", []))
        self.timeout = float(self.config.get("timeout", DEFAULT_TIMEOUT))
        self._n = 0

    def _id(self, prefix: str) -> str:
        self._n += 1
        return f"{prefix}-{self._n:03d}"

    async def scan(self, command: str, args: list[str],
                   env: dict[str, str] | None = None) -> ScanResult:
        target = " ".join([command, *args])
        result = ScanResult(target=target)

        # A canary file OUTSIDE whatever working dir the server uses, holding a
        # unique marker. Traversal that reads it will surface the marker.
        canary_dir = tempfile.mkdtemp(prefix="mcpsec_canary_")
        marker = f"CANARY_{uuid.uuid4().hex}"
        # The exists/missing probe paths must be byte-for-byte identical except
        # that one file exists and the other does not (same directory, same
        # filename length, shared prefix). Otherwise a tool that merely reflects
        # or measures its input string looks like it varies by file existence.
        canary = Path(canary_dir) / "probe_exists_aaaa.txt"
        canary.write_text(marker)
        missing = Path(canary_dir) / "probe_exists_zzzz.txt"

        server_env = {**os.environ, **(env or {})}
        params = StdioServerParameters(command=command, args=args, env=server_env)
        # Capture the server's stderr instead of letting it flood the console;
        # a server that dumps tracebacks there on hostile input is noisy but
        # the leak that matters is in the tool RESPONSE, checked separately.
        errlog = open(Path(canary_dir) / "server_stderr.log", "w")
        async with stdio_client(params, errlog=errlog) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                tools = (await session.list_tools()).tools
                result.tools = [t.name for t in tools]
                probe = _Probe(session, self.timeout)
                for tool in tools:
                    if tool.name in self.skip:
                        continue
                    schema = _tool_schema(tool)
                    overrides = self.arg_overrides.get(tool.name, {})
                    for param in _string_params(schema):
                        await self._probe_param(
                            probe, tool.name, schema, param, overrides,
                            canary, missing, marker, result,
                        )
        errlog.close()
        result.findings = _dedupe(result.findings)
        return result

    async def _probe_param(self, probe, tool, schema, param, overrides,
                           canary: Path, missing: Path, marker: str,
                           result: ScanResult) -> None:
        # 1) Traversal: confirmed read (marker leaks) or differential oracle.
        cname = canary.name
        leaked = False
        for tmpl in P.TRAVERSAL_TEMPLATES:
            payload = tmpl.format(canary=str(canary), canary_name=cname)
            text, _is_err, _to = await probe.call(
                tool, _build_args(schema, param, payload, overrides))
            if marker in _strip_echo(text, payload):
                result.findings.append(Finding(
                    id=self._id("READ"), severity="critical",
                    category="path-traversal", tool=tool,
                    title=f'Arbitrary file read via "{tool}"',
                    detail=f'Parameter "{param}" read a file outside the '
                           "server's directory; its contents came back.",
                    evidence=text[:200],
                    remediation="Resolve paths against an allowed base "
                                "directory and reject anything outside it."))
                leaked = True
                break
        if not leaked:
            exists_text, _e1, _t1 = await probe.call(
                tool, _build_args(schema, param, str(canary), overrides))
            missing_text, _e2, _t2 = await probe.call(
                tool, _build_args(schema, param, str(missing), overrides))
            a = _strip_echo(exists_text, str(canary)).strip()
            b = _strip_echo(missing_text, str(missing)).strip()
            if a != b:
                result.findings.append(Finding(
                    id=self._id("ORACLE"), severity="high",
                    category="path-traversal", tool=tool,
                    title=f'Out-of-scope path reached via "{tool}"',
                    detail=f'Parameter "{param}" replies differently for a '
                           "file that exists vs one that does not, both "
                           "outside the server's directory -- it is opening "
                           "or stat-ing paths it should refuse, and leaks "
                           "file existence even without returning contents.",
                    evidence=f"exists: {a[:80]!r} / missing: {b[:80]!r}",
                    remediation="Confine paths to an allowed base directory "
                                "and return a uniform error for anything "
                                "outside it (no present-vs-missing tell)."))

        # 2) Oversized input. A well-behaved tool rejects it (a protocol error,
        # OR a graceful "too large" reply). We only flag it when the tool hangs,
        # or when it clearly PROCESSED the whole input (echoed a large body back,
        # or reported the full length) with no sign of a size limit.
        text, is_err, timed_out = await probe.call(
            tool, _build_args(schema, param, P.OVERSIZED_STRING, overrides))
        if timed_out:
            result.findings.append(Finding(
                id=self._id("DOS"), severity="high", category="dos", tool=tool,
                title=f'Possible DoS: "{tool}" hangs on large input',
                detail=f'Parameter "{param}" did not respond within '
                       f"{self.timeout}s for a 200k-char string.",
                remediation="Enforce a maximum input size at the tool boundary."))
        elif not is_err:
            rejected = bool(P.SIZE_REJECTION.search(text))
            # Measure the response AFTER removing any echo of the huge input --
            # a tool that merely reflects the input back isn't doing unbounded
            # work (that's an echo finding, caught separately). A DoS signal is
            # a large NON-echoed body, or the tool reporting the full length.
            non_echo = _strip_echo(text, P.OVERSIZED_STRING)
            processed = (
                len(non_echo) > 20_000 or str(len(P.OVERSIZED_STRING)) in non_echo
            )
            if processed and not rejected:
                result.findings.append(Finding(
                    id=self._id("DOS"), severity="medium", category="dos",
                    tool=tool,
                    title=f'"{tool}" processes oversized input without a limit',
                    detail=f'Parameter "{param}" processed a 200k-char string '
                           "with no size limit; work/memory scales with input.",
                    remediation="Add an explicit maximum input length."))

        # 3) Output-injection: input reflected verbatim.
        for inj in P.INJECTION_STRINGS:
            text, is_err, _to = await probe.call(
                tool, _build_args(schema, param, inj, overrides))
            if not is_err and inj[:30] in text:
                result.findings.append(Finding(
                    id=self._id("ECHO"), severity="medium",
                    category="output-injection", tool=tool,
                    title=f'"{tool}" reflects input into output',
                    detail=f'Parameter "{param}" was echoed back verbatim; an '
                           "adversarial caller can smuggle instructions to the "
                           "calling model through this tool's output.",
                    evidence=text[:160],
                    remediation="Return structured data; don't echo raw input."))
                break

        # 4) Error leakage: stack traces, host paths, secrets. Project config
        # can add its own trigger strings via extra_payloads.
        for trig in [*P.ERROR_TRIGGERS, *self.extra_payloads]:
            text, _is_err, _to = await probe.call(
                tool, _build_args(schema, param, trig, overrides))
            self._scan_leakage(tool, param, text, result)

    def _scan_leakage(self, tool, param, text, result) -> None:
        for pat in P.SECRET_PATTERNS:
            if pat.search(text):
                result.findings.append(Finding(
                    id=self._id("SECRET"), severity="critical",
                    category="error-leakage", tool=tool,
                    title=f'Secret-like value in "{tool}" output',
                    detail="A response contained what looks like a credential.",
                    evidence=pat.search(text).group()[:40],
                    remediation="Never include secrets in tool output or errors."))
                return
        for pat in P.STACK_TRACE_PATTERNS:
            if pat.search(text):
                result.findings.append(Finding(
                    id=self._id("TRACE"), severity="medium",
                    category="error-leakage", tool=tool,
                    title=f'Stack trace leaked from "{tool}"',
                    detail="An error response exposed a stack trace / internals.",
                    evidence=text[:160],
                    remediation="Catch errors at the tool boundary; return a "
                                "generic message and log the detail server-side."))
                return
        for pat in P.HOST_PATH_PATTERNS:
            if pat.search(text):
                result.findings.append(Finding(
                    id=self._id("PATHLEAK"), severity="low",
                    category="error-leakage", tool=tool,
                    title=f'Absolute host path leaked from "{tool}"',
                    detail="A response contained an absolute host path "
                           "(reveals usernames / layout).",
                    evidence=pat.search(text).group()[:80],
                    remediation="Report paths relative to the base directory."))
                return


def _dedupe(findings: list[Finding]) -> list[Finding]:
    """Collapse repeat findings of the same kind on the same tool (e.g. a
    stack trace seen for several error triggers) to one entry."""
    seen: set[tuple[str | None, str, str]] = set()
    out = []
    for f in findings:
        key = (f.tool, f.category, f.title)
        if key not in seen:
            seen.add(key)
            out.append(f)
    return out


def run_scan(command: str, args: list[str], config: dict[str, Any] | None = None,
             env: dict[str, str] | None = None) -> ScanResult:
    """Synchronous entry point."""
    return asyncio.run(Scanner(config).scan(command, args, env))
