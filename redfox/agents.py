"""Specialist agents.

Each agent has one job and writes into shared engagement state. They never call
each other: the orchestrator plans, the engine routes, and every action still
passes the policy gate inside the runtime.

Agents only ever see real observations taken from the database, and their output
is schema-checked before it can change state.
"""

from __future__ import annotations

import json
from typing import Any

from .llm import LLMClient, LLMError
from .models import Scope, parse_target

ALLOWED_TASKS = {
    "recon": {"subfinder", "httpx"},
    "enum": {"nmap", "ffuf", "whatweb", "sslscan", "httpx"},
    "analysis": {"nuclei"},
    "triage": {"triage"},
    "validation": {"nuclei_validate", "authcheck", "http_probe"},
    "report": {"report"},
}

SEVERITIES = {"critical", "high", "medium", "low", "info"}
STATUSES = {"candidate", "validated", "rejected", "inconclusive"}

ORCHESTRATOR_SYSTEM = """You are the orchestrator of an AUTHORIZED penetration test.
You do not run tools. You plan work for specialist agents and you are scored on
coverage, evidence quality and not wasting actions.

Hard rules:
- Only propose targets that appear in the engagement scope. Out-of-scope work is refused.
- Prefer breadth first, then depth on what the real output showed.
- Propose `triage` once findings exist; `validation` for candidates you want proven;
  `report` when the assessment is done or nothing useful remains.
- Never claim a vulnerability exists. Validation proves it later, with evidence.

Available tools:
{catalog}

Reply with ONE JSON object, no prose:
{"reasoning": "<one or two sentences>",
  "tasks": [{"agent": "recon|enum|analysis|triage|validation|report",
             "kind": "<task kind>",
             "target": "<in-scope target or empty for triage/report>",
             "reason": "<why>"}],
  "done": false}

Return 1 to 4 tasks. Return an empty list only when the report task has already
run, or when every allowed target has been covered and no candidate remains.
Set "done": true only in those two cases.
Task kinds by agent: recon->subfinder|httpx, enum->nmap|ffuf|whatweb|sslscan|httpx,
analysis->nuclei, triage->triage, validation->nuclei_validate|authcheck|http_probe,
report->report."""

TRIAGE_SYSTEM = """You are the vulnerability triage specialist on an AUTHORIZED engagement.
You receive candidates extracted from real tool output, each with evidence ids.

Rules:
- A candidate is only `rejected` if the evidence does not support it (e.g. a
  discovered path is not itself a vulnerability, technology detection is not a
  vulnerability).
- Never invent a finding, a CVE, or a CVSS score that the evidence does not support.
- Set `validated` ONLY if the candidate's own evidence already proves exploitation;
  otherwise leave it `candidate` so the validation agent can prove it.
- Severity must reflect real impact: exposed credentials/config = high, discoverable
  but non-sensitive path = info/low.

Reply with ONE JSON object:
{"findings": [{"fingerprint": "<as given>", "title": "<short>",
  "severity": "critical|high|medium|low|info", "cvss": <number or null>,
  "status": "candidate|validated|rejected|inconclusive",
  "description": "<what the evidence shows>",
  "remediation": "<concrete fix>"}]}"""

VALIDATOR_SYSTEM = """You are the exploit-validation specialist on an AUTHORIZED engagement.
Your job is to prove or disprove candidate findings with the least intrusive check
that settles it. You never propose destructive actions.

Methods:
- "nuclei_validate": re-run the exact template ids that produced the candidate.
- "http_probe": one GET/POST you specify, compared against the evidence.
- "authcheck": test operator-supplied credentials against the configured login.

Reply with ONE JSON object:
{"validations": [{"fingerprint": "<as given>", "method": "...",
  "template_ids": ["..."], "url": "<in scope>", "note": "<what this proves>"}]}
If nothing can be validated, reply {"validations": []}."""

REPORTER_SYSTEM = """You are the technical writer on an AUTHORIZED engagement.
Write an executive summary and short remediation notes using ONLY the findings
provided. Do not add findings, do not upgrade severity, do not mention tools that
were not used. Be plain and specific.

Reply with ONE JSON object:
{"executive_summary": "<3-6 sentences>",
 "remediation": {"<fingerprint>": "<one or two sentences>"}}"""


class AgentError(RuntimeError):
    pass


def _truncate(obj: Any, limit: int = 12000) -> str:
    text = json.dumps(obj, default=str)
    return text if len(text) <= limit else text[:limit] + '... [truncated]"}'


class Orchestrator:
    name = "orchestrator"

    def __init__(self, llm: LLMClient, catalog: str) -> None:
        self.llm = llm
        self.catalog = catalog

    async def plan(self, state: dict[str, Any]) -> dict[str, Any]:
        system = ORCHESTRATOR_SYSTEM.replace("{catalog}", self.catalog)
        prompt = (
            f"Engagement state:\n{_truncate(state)}\n\n"
            "Plan the next tasks. Use exact targets from the state."
        )
        reply = await self.llm.json_reply(system, prompt, max_tokens=600)
        return validate_plan(reply.data, state)


def validate_plan(data: dict[str, Any], state: dict[str, Any]) -> dict[str, Any]:
    """Reject any task that is not in the closed vocabulary or out of scope."""
    scope = Scope.from_dict(state["scope"])
    tasks: list[dict[str, Any]] = []
    for raw in (data.get("tasks") or [])[:4]:
        if not isinstance(raw, dict):
            continue
        agent = str(raw.get("agent", "")).lower()
        kind = str(raw.get("kind", "")).lower()
        target = str(raw.get("target", "")).strip()
        if agent not in ALLOWED_TASKS or kind not in ALLOWED_TASKS[agent]:
            continue
        if kind in {"triage", "report"}:
            tasks.append({"agent": agent, "kind": kind, "target": "", "reason": raw.get("reason", "")})
            continue
        try:
            parsed = parse_target(target)
        except Exception:
            continue
        allowed, _ = scope.check(parsed)
        if not allowed:
            continue
        tasks.append({"agent": agent, "kind": kind, "target": target,
                      "reason": str(raw.get("reason", ""))[:300]})
    done = bool(data.get("done")) or not tasks
    return {"reasoning": str(data.get("reasoning", ""))[:600],
            "tasks": tasks, "done": done}


class Triage:
    name = "triage"

    def __init__(self, llm: LLMClient) -> None:
        self.llm = llm

    async def review(self, candidates: list[dict[str, Any]]) -> list[dict[str, Any]]:
        if not candidates:
            return []
        prompt = ("Candidates extracted from real tool output:\n"
                  + _truncate(candidates, 14000))
        reply = await self.llm.json_reply(TRIAGE_SYSTEM, prompt, max_tokens=900)
        findings = []
        for raw in reply.data.get("findings") or []:
            if not isinstance(raw, dict):
                continue
            fingerprint = str(raw.get("fingerprint", "")).strip()
            if not fingerprint:
                continue
            severity = str(raw.get("severity", "info")).lower()
            status = str(raw.get("status", "candidate")).lower()
            findings.append({
                "fingerprint": fingerprint,
                "title": str(raw.get("title", ""))[:200],
                "severity": severity if severity in SEVERITIES else "info",
                "cvss": _as_float(raw.get("cvss")),
                "status": status if status in STATUSES else "candidate",
                "description": str(raw.get("description", ""))[:4000],
                "remediation": str(raw.get("remediation", ""))[:2000],
            })
        return findings


class Validator:
    name = "validation"

    def __init__(self, llm: LLMClient) -> None:
        self.llm = llm

    async def plan(self, candidates: list[dict[str, Any]],
                   auth_spec: dict[str, Any] | None) -> list[dict[str, Any]]:
        if not candidates:
            return []
        prompt = (
            "Candidates awaiting proof:\n" + _truncate(candidates, 10000)
            + "\n\nConfigured login for authcheck (may be null): "
            + _truncate(auth_spec, 2000)
        )
        reply = await self.llm.json_reply(VALIDATOR_SYSTEM, prompt, max_tokens=700)
        out = []
        for raw in reply.data.get("validations") or []:
            if not isinstance(raw, dict):
                continue
            fingerprint = str(raw.get("fingerprint", "")).strip()
            method = str(raw.get("method", "")).lower()
            if not fingerprint or method not in {"nuclei_validate", "http_probe", "authcheck"}:
                continue
            out.append({
                "fingerprint": fingerprint,
                "method": method,
                "template_ids": [str(t) for t in (raw.get("template_ids") or [])][:3],
                "url": str(raw.get("url", ""))[:500],
                "note": str(raw.get("note", ""))[:300],
            })
        return out


class Reporter:
    name = "reporting"

    def __init__(self, llm: LLMClient) -> None:
        self.llm = llm

    async def write(self, findings: list[dict[str, Any]], meta: dict[str, Any]) -> dict[str, Any]:
        prompt = ("Engagement: " + _truncate(meta, 2000)
                  + "\nValidated/candidate findings:\n" + _truncate(findings, 12000))
        reply = await self.llm.json_reply(REPORTER_SYSTEM, prompt, max_tokens=1200)
        remediation = reply.data.get("remediation") or {}
        if not isinstance(remediation, dict):
            remediation = {}
        return {
            "executive_summary": str(reply.data.get("executive_summary", ""))[:4000],
            "remediation": {str(k): str(v)[:1000] for k, v in remediation.items()},
        }


def _as_float(value: Any) -> float | None:
    try:
        num = float(value)
    except (TypeError, ValueError):
        return None
    return num if 0.0 <= num <= 10.0 else None


def build_agents(llm: LLMClient, catalog: str) -> dict[str, Any]:
    return {
        "orchestrator": Orchestrator(llm, catalog),
        "triage": Triage(llm),
        "validation": Validator(llm),
        "report": Reporter(llm),
    }