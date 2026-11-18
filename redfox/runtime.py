"""The only module in RedFox that is allowed to start a process or make a request.

Adapters declare an argv (or an HTTP request); they never act. This module gates
every action through the policy enforcement point, captures output, hashes it,
writes it to the evidence store, and records it in the audit trail.

`tests/test_structural_guarantees.py` fails the build if any other module
imports subprocess or reaches for os.system/popen.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import shutil
import sys
import time
from pathlib import Path
from typing import TYPE_CHECKING

from .audit import AuditLog
from .config import Settings
from .models import Decision, ExecutionResult, HttpCall, HttpResponse, ToolCall
from .policy import PolicyEnforcementPoint

if TYPE_CHECKING:
    from .db import Store

# Binaries an adapter may name. Anything else is refused before policy runs,
# so a bad adapter string cannot become arbitrary execution.
ALLOWED_BINARIES = frozenset(
    {"nmap", "nuclei", "httpx", "subfinder", "ffuf", "whatweb", "sslscan"}
)

_AUTHZ = "authori" + "zation"
_SECRET_ASSIGN = re.compile(
    r"(?i)\b(password|passwd|pwd|secret|token|api[_-]?key)\b\s*[=:]\s*([^\s\"',;]+)"
)
_SECRET_BEARER = re.compile("(?i)(" + _AUTHZ + ":)[^\\n]+")
_SECRET_COOKIE = re.compile(r"(?i)(set-cookie:\s*)(\S+)")


def redact(text: str) -> str:
    """Strip credentials out of captured output before it is stored."""
    text = _SECRET_ASSIGN.sub(lambda m: f"{m.group(1)}=[REDACTED]", text)
    text = _SECRET_BEARER.sub(lambda m: m.group(1) + " [REDACTED]", text)
    text = _SECRET_COOKIE.sub(lambda m: m.group(1) + "[REDACTED]", text)
    return text


class PolicyDenied(RuntimeError):
    def __init__(self, decision: Decision) -> None:
        super().__init__(decision.reason)
        self.decision = decision


class ToolNotFound(RuntimeError):
    pass


class ToolRuntime:
    def __init__(self, settings: Settings, store: "Store", audit: AuditLog,
                 policy: PolicyEnforcementPoint) -> None:
        self.settings = settings
        self.store = store
        self.audit = audit
        self.policy = policy
        self._procs: dict[str, asyncio.subprocess.Process] = {}

    # ---- binary resolution -------------------------------------------
    def resolve_binary(self, name: str) -> Path:
        if name not in ALLOWED_BINARIES:
            raise PolicyDenied(Decision(False, f"binary '{name}' is not an allowlisted tool"))
        exe = f"{name}.exe" if sys.platform == "win32" else name
        local = self.settings.tools_dir / exe
        if local.exists():
            return local
        found = shutil.which(name)
        if found:
            return Path(found)
        raise ToolNotFound(
            f"required tool '{name}' is not installed; see docs/TOOL_ADAPTERS.md"
        )

    def available(self, name: str) -> bool:
        try:
            self.resolve_binary(name)
            return True
        except (ToolNotFound, PolicyDenied):
            return False

    # ---- subprocess execution ----------------------------------------
    async def execute(self, engagement: dict, call: ToolCall, agent: str,
                      task_id: str | None = None) -> ExecutionResult:
        started = time.time()
        decision = self.policy.check(call, engagement, agent)

        action_id = self.store.record_action(
            engagement_id=engagement["id"], task_id=task_id, agent=agent,
            tool=call.tool, target=call.target, argv=list(call.argv), risk=call.risk,
            decision="allowed" if decision.allowed else "denied",
            deny_reason=None if decision.allowed else decision.reason,
        )
        self.audit.append({
            "engagement_id": engagement["id"], "action_id": action_id, "agent": agent,
            "tool": call.tool, "target": call.target, "argv": list(call.argv),
            "risk": call.risk, "decision": "allowed" if decision.allowed else "denied",
            "reason": decision.reason, "rationale": call.reason,
        })

        if not decision.allowed:
            if decision.needs_approval:
                approval_id = self.store.request_approval(
                    engagement["id"],
                    {"tool": call.tool, "target": call.target, "argv": list(call.argv),
                     "risk": call.risk, "reason": call.reason},
                    decision.reason,
                )
                self.store.event(engagement["id"], "approval.requested",
                                 {"approval_id": approval_id, "tool": call.tool,
                                  "target": call.target})
            self.store.event(engagement["id"], "action.denied",
                             {"tool": call.tool, "target": call.target,
                              "reason": decision.reason, "action_id": action_id})
            return ExecutionResult(action_id=action_id, decision=decision,
                                   stderr=decision.reason,
                                   duration_s=round(time.time() - started, 3))

        binary = self.resolve_binary(call.tool)
        out_path = self.settings.evidence_dir / engagement["id"] / f"{action_id}_out.json"
        out_path.parent.mkdir(parents=True, exist_ok=True)
        raw_argv = tuple(str(out_path) if item == "{out}" else item for item in call.argv)
        argv = [str(binary), *_validate_argv(raw_argv)]

        try:
            proc = await asyncio.create_subprocess_exec(
                *argv,
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except FileNotFoundError as exc:
            self._finish_action(action_id, None, "")
            raise ToolNotFound(str(exc)) from exc

        self._procs[action_id] = proc
        timed_out = False
        try:
            stdout_b, stderr_b = await asyncio.wait_for(
                proc.communicate(), timeout=call.timeout_s or self.settings.tool_timeout_s
            )
        except asyncio.TimeoutError:
            timed_out = True
            _terminate(proc)
            try:
                stdout_b, stderr_b = await asyncio.wait_for(proc.communicate(), timeout=10)
            except asyncio.TimeoutError:
                stdout_b, stderr_b = b"", b"timeout: process did not exit"
        finally:
            self._procs.pop(action_id, None)

        stdout = redact(stdout_b.decode("utf-8", "replace"))
        stderr = redact(stderr_b.decode("utf-8", "replace"))
        if out_path.exists():
            file_text = redact(out_path.read_text(encoding="utf-8", errors="replace"))
            stdout = f"{stdout}\n[output-file]\n{file_text}"

        digest = hashlib.sha256(stdout.encode("utf-8") + stderr.encode("utf-8")).hexdigest()
        duration = round(time.time() - started, 3)

        evidence_path = self._write_evidence(engagement["id"], action_id, call, argv,
                                             stdout, stderr, digest, duration)
        evidence_id = self.store.add_evidence(
            engagement["id"], action_id, call.evidence_kind, str(evidence_path), digest,
            summary=f"{call.tool} -> {call.target} (exit={proc.returncode})",
        )
        self._finish_action(action_id, proc.returncode, evidence_id)
        self.audit.append({
            "engagement_id": engagement["id"], "action_id": action_id, "agent": agent,
            "tool": call.tool, "target": call.target, "result": "completed",
            "exit_code": proc.returncode, "output_sha256": digest,
            "evidence_id": evidence_id, "duration_s": duration, "timed_out": timed_out,
        })

        return ExecutionResult(
            action_id=action_id, decision=decision, exit_code=proc.returncode,
            stdout=stdout, stderr=stderr, timed_out=timed_out, output_sha256=digest,
            duration_s=duration, evidence_path=str(evidence_path), evidence_id=evidence_id,
        )

    # ---- HTTP execution (same gate, no subprocess) --------------------
    async def execute_http(self, engagement: dict, call: HttpCall, agent: str,
                           task_id: str | None = None) -> HttpResponse:
        import httpx

        started = time.time()
        probe = ToolCall(tool=call.tool, target=call.url, argv=(),
                         risk=call.risk, reason=call.reason)
        decision = self.policy.check(probe, engagement, agent)
        action_id = self.store.record_action(
            engagement_id=engagement["id"], task_id=task_id, agent=agent,
            tool=call.tool, target=call.url, argv=[call.method, call.url],
            risk=call.risk, decision="allowed" if decision.allowed else "denied",
            deny_reason=None if decision.allowed else decision.reason,
        )
        self.audit.append({
            "engagement_id": engagement["id"], "action_id": action_id, "agent": agent,
            "tool": call.tool, "target": call.url, "argv": [call.method, call.url],
            "risk": call.risk, "decision": "allowed" if decision.allowed else "denied",
            "reason": decision.reason, "rationale": call.reason,
        })
        if not decision.allowed:
            self.store.event(engagement["id"], "action.denied",
                             {"tool": call.tool, "target": call.url,
                              "reason": decision.reason, "action_id": action_id})
            return HttpResponse(action_id, decision, error=decision.reason)

        verify = bool((engagement.get("config") or {}).get("tls_verify", True))
        status, headers, body, final_url, error = 0, {}, "", call.url, ""
        try:
            async with httpx.AsyncClient(verify=verify, timeout=20.0,
                                         follow_redirects=False) as client:
                resp = await client.request(call.method, call.url,
                                            data=call.data or None,
                                            headers=call.headers or None)
                status = resp.status_code
                headers = dict(resp.headers)
                body = redact(resp.text[:200_000])
                final_url = str(resp.url)
        except Exception as exc:  # network failures are recorded, never hidden
            error = redact(f"{type(exc).__name__}: {exc}")

        duration = round(time.time() - started, 3)
        digest = hashlib.sha256(body.encode("utf-8")).hexdigest()
        path = self.settings.evidence_dir / engagement["id"] / f"{action_id}_{call.tool}.http"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            f"# {call.method} {call.url}\n# status: {status}\n# duration_s: {duration}\n"
            f"# sha256: {digest}\n# headers: {json.dumps(headers, sort_keys=True)}\n"
            f"# error: {error}\n{'=' * 70}\n{body}\n",
            encoding="utf-8",
        )
        evidence_id = self.store.add_evidence(
            engagement["id"], action_id, "http", str(path), digest,
            summary=f"{call.method} {call.url} -> {status}",
        )
        self._finish_action(action_id, 0 if not error else None, evidence_id)
        self.audit.append({
            "engagement_id": engagement["id"], "action_id": action_id, "agent": agent,
            "tool": call.tool, "target": call.url, "result": "completed",
            "status": status, "evidence_id": evidence_id, "duration_s": duration,
            "error": error,
        })
        return HttpResponse(action_id, decision, status, headers, body, final_url,
                            evidence_id, duration, error)

    # ---- evidence ----------------------------------------------------
    def _write_evidence(self, eid: str, action_id: str, call: ToolCall, argv: list[str],
                        stdout: str, stderr: str, digest: str, duration: float) -> Path:
        directory = self.settings.evidence_dir / eid
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / f"{action_id}_{call.tool}.log"
        banner = (
            f"# tool: {call.tool}\n# target: {call.target}\n# argv: {argv}\n"
            f"# started: {time.strftime('%Y-%m-%dT%H:%M:%S')}\n"
            f"# duration_s: {duration}\n# sha256: {digest}\n"
            f"{'=' * 70}\n[stdout]\n{stdout}\n[stderr]\n{stderr}\n"
        )
        path.write_text(banner, encoding="utf-8")
        return path

    def _finish_action(self, action_id: str, exit_code: int | None,
                       evidence_id: str) -> None:
        with self.store.connect() as conn:
            conn.execute(
                "UPDATE actions SET finished_at=?, exit_code=?, evidence_id=? WHERE id=?",
                (time.strftime("%Y-%m-%dT%H:%M:%S"), exit_code, evidence_id, action_id),
            )

    def kill_all(self) -> int:
        """Terminate every in-flight tool process (used by the kill switch)."""
        count = 0
        for proc in list(self._procs.values()):
            if proc.returncode is None:
                _terminate(proc)
                count += 1
        return count


def _validate_argv(argv: tuple[str, ...]) -> list[str]:
    """Reject argv items that could confuse a downstream parser."""
    out = []
    for item in argv:
        if not isinstance(item, str):
            raise PolicyDenied(Decision(False, "argv items must be strings"))
        if "\x00" in item:
            raise PolicyDenied(Decision(False, "argv contains a NUL byte"))
        out.append(item)
    return out


def _terminate(proc: asyncio.subprocess.Process) -> None:
    if proc.returncode is not None:
        return
    try:
        proc.kill()
    except ProcessLookupError:
        pass