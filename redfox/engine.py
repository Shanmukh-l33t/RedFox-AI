"""Campaign engine: the state machine that drives a resumable engagement.

Loop: take a durable task, run it through the policy-gated runtime (or hand it
to an LLM agent), write results into shared state, checkpoint. A crash leaves
`running` tasks behind; `resume()` requeues them and continues.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from . import impact, report, validation
from .adapters.registry import ToolBox
from .agents import build_agents
from .audit import AuditLog
from .config import Settings
from .db import Store
from .llm import LLMClient, LLMError
from .models import Authorization, ExecutionResult, Scope, ScopeError, ToolCall, parse_target
from .policy import PolicyEnforcementPoint
from .runtime import ToolNotFound, ToolRuntime
from .secrets import MissingSecret, redacted

TOOL_TASKS = {"subfinder", "nmap", "httpx", "nuclei", "nuclei_validate",
              "ffuf", "whatweb", "sslscan"}
AGENT_TASKS = {"triage", "report"}


def fingerprint(*parts: str) -> str:
    return hashlib.sha1("|".join(parts).encode("utf-8")).hexdigest()


class Campaign:
    def __init__(self, settings: Settings, store: Store, audit: AuditLog,
                 policy: PolicyEnforcementPoint, llm: LLMClient | None = None) -> None:
        self.settings = settings
        self.store = store
        self.audit = audit
        self.policy = policy
        self.runtime = ToolRuntime(settings, store, audit, policy)
        self.toolbox = ToolBox(self.runtime)
        self.llm = llm or LLMClient(settings)
        self.wordlist = Path(__file__).resolve().parent.parent / "tools" / "wordlists" / "common.txt"
        self._agents = build_agents(self.llm, self.toolbox.catalog_text())

    async def write_report(self, engagement_id: str) -> dict[str, Any]:
        """Re-render the report from stored state, without scanning anything."""
        eng = self.store.get_engagement(engagement_id)
        if not eng:
            raise ValueError(f"unknown engagement {engagement_id}")
        return await self._report(eng, Scope.from_dict(eng["scope"]))

    # ---- entry points -------------------------------------------------
    async def run(self, engagement_id: str, max_steps: int | None = None) -> dict[str, Any]:
        eng = self.store.get_engagement(engagement_id)
        if not eng:
            raise ValueError(f"unknown engagement {engagement_id}")
        try:
            auth = Authorization.from_dict(eng["authorization"])
        except ScopeError as exc:
            raise ScopeError(f"engagement cannot start: {exc}") from exc
        scope = Scope.from_dict(eng["scope"])
        self._agents = build_agents(self.llm, self.toolbox.catalog_text())

        requeued = self.store.reset_running_tasks(engagement_id)
        retried = self.store.retry_failed_tasks(engagement_id)
        if requeued or retried:
            self.store.event(engagement_id, "campaign.resume",
                             {"requeued": requeued, "retried": retried})
        self.store.set_status(engagement_id, "running")
        self.policy.bind_approvals(
            lambda tool, target: self.store.approved_for(engagement_id, tool, target))
        self.llm.on_usage = lambda reply: self.store.event(
            engagement_id, "llm.usage",
            {"model": reply.model, "in": reply.input_tokens, "out": reply.output_tokens})
        for _ in self.store.approved_unconsumed(engagement_id):
            already = any(t["kind"] == "impact" and t["state"] == "pending"
                          for t in self.store.tasks_for(engagement_id))
            if not already:
                self.store.add_task(engagement_id, "postexploit", "postexploit", "impact",
                                    {"reason": "operator approved an intrusive action"})
        self.audit.append({"engagement_id": engagement_id, "event": "campaign.start",
                           "operator": auth.operator,
                           "authorization_ref": auth.authorization_ref,
                           "autonomy": eng["autonomy"],
                           "model": self.llm.model or self.llm.provider})

        budget = max_steps or self.settings.max_steps
        steps = 0
        consecutive_denials = 0
        denial_spike = False

        while steps < budget:
            if self.policy.killed():
                self.store.set_status(engagement_id, "halted")
                self.store.event(engagement_id, "campaign.halted", {"reason": "kill switch"})
                break

            waiting = self.store.pending_approval(engagement_id)
            if waiting:
                self.store.set_status(engagement_id, "awaiting_approval")
                self.store.event(engagement_id, "campaign.awaiting_approval",
                                 {"approval_id": waiting["id"], "reason": waiting["reason"]})
                break

            # The planner decides what to do next, but not whether the engagement
            # gets a report: on the final round the report is produced regardless
            # of what is still queued or what the model would prefer.
            if steps + 1 >= budget and not self._report_done(engagement_id):
                self.store.event(engagement_id, "plan.report_forced",
                                 {"steps": steps, "budget": budget})
                await self._report(eng, scope)
                steps += 1
                break

            task = self.store.next_task(engagement_id)
            if task is None:
                plan = await self._agents["orchestrator"].plan(self._state(eng, scope))
                self.store.event(engagement_id, "plan.proposed", plan)
                if not plan["tasks"]:
                    plan = self._floor_plan(eng, scope)
                    if not plan["tasks"]:
                        break
                    self.store.event(engagement_id, "plan.floor", plan)
                enqueued = 0
                for item in plan["tasks"]:
                    if item["target"] and self.store.task_already_done(
                            engagement_id, item["kind"], item["target"]):
                        self.store.event(engagement_id, "plan.duplicate_skipped", item)
                        continue
                    self.store.add_task(engagement_id, item["agent"], item["agent"],
                                        item["kind"], item)
                    enqueued += 1
                if not enqueued:
                    self.store.event(engagement_id, "campaign.no_new_work", plan)
                    break
                steps += 1
                continue

            if not self.store.claim_task(task["id"]):
                continue
            try:
                outcome = await self._dispatch(eng, scope, task)
                self.store.finish_task(task["id"], "done", outcome)
                consecutive_denials = consecutive_denials + 1 if outcome.get("denied") else 0
            except ToolNotFound as exc:
                self.store.finish_task(task["id"], "failed", {"error": str(exc)})
                self.store.add_memory("tool_missing", task["kind"], str(exc), engagement_id)
                outcome = {"error": str(exc)}
                consecutive_denials = 0
            except LLMError as exc:
                self.store.finish_task(task["id"], "failed", {"error": str(exc)})
                self.store.set_status(engagement_id, "paused")
                self.store.event(engagement_id, "campaign.paused", {"reason": str(exc)})
                raise
            except Exception as exc:  # a task bug must not take the campaign down
                import traceback

                self.store.finish_task(task["id"], "failed",
                                       {"error": f"{type(exc).__name__}: {exc}"})
                self.store.event(engagement_id, "task.error",
                                 {"kind": task["kind"],
                                  "error": f"{type(exc).__name__}: {exc}"[:300],
                                  "trace": traceback.format_exc()[-800:]})
                outcome = {"error": str(exc)}
                consecutive_denials = 0
            steps += 1

            if consecutive_denials >= 3:
                denial_spike = True
                self.store.set_status(engagement_id, "halted")
                self.store.event(engagement_id, "campaign.halted",
                                 {"reason": "repeated out-of-scope or denied actions"})
                break
            if self.store.get_engagement(engagement_id)["status"] == "completed":
                break

        eng = self.store.get_engagement(engagement_id) or eng
        if eng["status"] == "running":
            waiting = self.store.pending_approval(engagement_id)
            report_done = self._report_done(engagement_id)
            if waiting:
                # Hitting the budget while an approval is outstanding still means
                # the campaign is blocked on a human, not finished.
                self.store.set_status(engagement_id, "awaiting_approval")
            elif report_done:
                self.store.set_status(engagement_id, "completed")
            else:
                # Out of budget without a report: paused is the honest status.
                self.store.set_status(engagement_id, "paused")
                self.store.event(engagement_id, "campaign.budget_exhausted",
                                 {"steps": steps})
        return self.summary(engagement_id, denial_spike=denial_spike, steps=steps)

    # ---- dispatch -----------------------------------------------------
    def _report_done(self, engagement_id: str) -> bool:
        return any(t["kind"] == "report" and t["state"] == "done"
                   for t in self.store.tasks_for(engagement_id))

    async def _dispatch(self, eng: dict, scope: Scope, task: dict) -> dict[str, Any]:
        kind = task["kind"]
        if kind in TOOL_TASKS:
            return await self._run_tool(eng, scope, task)
        if kind == "authcheck":
            return await self._run_authcheck(eng, task)
        if kind == "triage":
            return await self._triage(eng)
        if kind in {"validation", "http_probe"}:
            # A planner may ask to "probe this URL"; the validator owns which
            # candidates get proven and how, so one validation pass covers it.
            return await self._validation(eng, scope)
        if kind == "impact":
            return await self._impact(eng)
        if kind == "report":
            return await self._report(eng, scope)
        # A model must never be able to end a campaign by naming something we
        # do not implement. Record it and move on.
        self.store.event(eng["id"], "task.unsupported", {"kind": kind,
                                                         "agent": task.get("agent", "")})
        return {"error": f"unsupported task kind {kind}"}

    async def _run_tool(self, eng: dict, scope: Scope, task: dict) -> dict[str, Any]:
        adapter = self.toolbox.get(task["kind"])
        if adapter is None:
            return {"error": f"no adapter for {task['kind']}"}
        if not adapter.available(self.runtime):
            raise ToolNotFound(
                f"{adapter.binary} is not installed; adapter {adapter.name} cannot run"
            )
        target_raw = task["payload"].get("target") or ""
        target = parse_target(target_raw)
        ctx = self._tool_context(eng, scope, task)
        allowed, denied, observations = await self._execute_adapter(
            eng, adapter, target, ctx, task["agent"], task["id"])
        self.store.add_memory(
            "tool_result", adapter.name,
            json.dumps({"engagement": eng["id"], "observations": observations,
                        "allowed": allowed, "denied": denied}),
            eng["id"],
        )
        return {"tool": adapter.name, "observations": observations,
                "allowed": allowed, "denied": denied}

    async def _execute_adapter(self, eng: dict, adapter: Any, target: Any, ctx: dict,
                               agent: str, task_id: str) -> tuple[int, int, int]:
        allowed = denied = observations = 0
        for call in adapter.plan(target, ctx):
            result = await self.runtime.execute(eng, call, agent, task_id)
            if not result.decision.allowed:
                denied += 1
                continue
            allowed += 1
            parsed = adapter.parse(result)
            observations += len(parsed)
            self._ingest(eng, parsed, result, call)
        return allowed, denied, observations

    async def _run_authcheck(self, eng: dict, task: dict) -> dict[str, Any]:
        """Planner-requested credential check against the configured login form."""
        spec = dict((eng.get("config") or {}).get("auth_check") or {})
        url = task["payload"].get("target") or spec.get("url") or ""
        if not spec or not url:
            return {"skipped": "no auth_check spec configured"}
        from types import SimpleNamespace

        from .adapters.auth import AuthCheck

        checker = AuthCheck()
        allowed = denied = 0
        accepted = 0
        try:
            calls = checker.plan(url, spec)
        except MissingSecret as exc:
            self.store.event(eng["id"], "secrets.missing", {"error": str(exc)[:300]})
            return {"error": str(exc), "skipped": "credential reference unresolved"}
        for call in calls:
            response = await self.runtime.execute_http(eng, call, task["agent"], task["id"])
            if not response.decision.allowed:
                denied += 1
                continue
            allowed += 1
            observation = checker.parse(call, response, spec)
            if observation.data.get("accepted"):
                accepted += 1
            self._ingest(eng, [observation],
                         SimpleNamespace(evidence_id=response.evidence_id,
                                         evidence_path=""), call)
        return {"authcheck": {"allowed": allowed, "denied": denied,
                              "accepted": accepted}}

    async def _validation(self, eng: dict, scope: Scope) -> dict[str, Any]:
        candidates = [f for f in self.store.findings_for(eng["id"])
                      if f["status"] == "candidate"
                      # A reachable path is an observation, not a claim to prove.
                      and not (f["source_tool"] == "ffuf" and f["severity"] == "info")]
        if not candidates:
            return {"skipped": "no candidates"}
        payload = [{
            "fingerprint": f["fingerprint"], "title": f["title"],
            "severity": f["severity"], "location": f["location"],
            "description": f["description"][:400], "template_id": f.get("template_id", ""),
            "source_tool": f["source_tool"],
        } for f in candidates[:15]]
        try:
            plan = await self._agents["validation"].plan(
                payload, redacted((eng.get("config") or {}).get("auth_check")))
        except LLMError as exc:
            self.store.event(eng["id"], "validation.error", {"error": str(exc)[:300]})
            plan = []
        planned = {item["fingerprint"] for item in plan}
        plan.extend(_fallback_validations(
            [p for p in payload if p["fingerprint"] not in planned],
            (eng.get("config") or {}).get("auth_check")))
        proven = inconclusive = 0
        for item in plan:
            finding = self.store.finding_by_fingerprint(eng["id"], item["fingerprint"])
            if not finding:
                continue
            method = item["method"]
            evidence_ids: list[str] = []
            confirmed = False
            reproduction: list[str] = []

            if method == "nuclei_validate":
                adapter = self.toolbox.get("nuclei_validate")
                template_ids = item["template_ids"] or [finding.get("template_id", "")]
                template_ids = [t for t in template_ids if t]
                if adapter and template_ids and adapter.available(self.runtime):
                    url = finding.get("location") or finding["asset"]
                    ctx = {"scope": scope, "template_ids": template_ids,
                           "open_ports": [], "config": eng.get("config") or {}}
                    try:
                        before = len(self.store.findings_for(eng["id"]))
                        await self._execute_adapter(eng, adapter, parse_target(url), ctx,
                                                    "validation", "")
                        refreshed = self.store.finding_by_fingerprint(
                            eng["id"], item["fingerprint"])
                        confirmed = bool(refreshed and refreshed["status"] == "validated")
                        evidence_ids = (refreshed or {}).get("evidence_ids", [])
                        reproduction = [f"Re-ran nuclei template(s): {', '.join(template_ids)}"]
                        if not confirmed:
                            confirmed = len(self.store.findings_for(eng["id"])) > before
                    except ToolNotFound:
                        confirmed = False

            elif method == "authcheck":
                spec = dict((eng.get("config") or {}).get("auth_check") or {})
                login_url = item.get("url") or spec.get("url") or ""
                if login_url:
                    from .adapters.auth import AuthCheck
                    checker = AuthCheck()
                    for http_call in checker.plan(login_url, spec):
                        response = await self.runtime.execute_http(
                            eng, http_call, "validation")
                        obs = checker.parse(http_call, response, spec)
                        if obs.data.get("accepted"):
                            # The proof belongs to a credential finding, not to
                            # whatever candidate happened to point at the login URL.
                            username = obs.data.get("username", "")
                            cred_fp = fingerprint("auth", login_url, username)
                            self.store.upsert_finding(
                                eng["id"], cred_fp,
                                f"Valid credentials for {login_url}", "critical",
                                login_url,
                                f"Operator-supplied credentials for '{username}' were "
                                f"accepted by {login_url} (HTTP {response.status}).",
                                status="validated", location=login_url,
                                evidence_ids=[response.evidence_id],
                                reproduction=[f"POST {login_url} with the reported "
                                              "credentials",
                                              f"Observed HTTP {response.status} with "
                                              "authenticated content"],
                                source_tool="authcheck",
                            )
                            evidence_ids.append(response.evidence_id)
                    reproduction = [f"POST {login_url} with operator-supplied credentials "
                                    "(see the credential finding)"]
            elif method == "http_probe":
                url = item.get("url") or finding.get("location") or finding["asset"]
                parts = urlsplit(url)
                if parts.query and "=" in parts.query:
                    param = parts.query.split("=")[0]
                    result = await validation.probe_reflection(
                        self.runtime, eng, url, param, "validation")
                    if not result["confirmed"]:
                        result = await validation.probe_sql_injection(
                            self.runtime, eng, url, "validation")
                else:
                    marker = _exposure_marker(finding)
                    result = await validation.confirm_exposure(
                        self.runtime, eng, url, marker, "validation")
                confirmed = result["confirmed"]
                evidence_ids = result.get("evidence_ids", [])
                reproduction = [f"Safe PoC: {result['reason']}"]
                if result.get("payloads"):
                    reproduction.append("Payloads: " + json.dumps(result["payloads"]))

            if evidence_ids:
                self.store.update_finding(eng["id"], item["fingerprint"],
                                          evidence_ids=evidence_ids)
            if reproduction:
                existing = (self.store.finding_by_fingerprint(
                    eng["id"], item["fingerprint"]) or {}).get("reproduction", [])
                self.store.update_finding(eng["id"], item["fingerprint"],
                                          reproduction=existing + reproduction)
            if confirmed:
                proven += 1
                self.store.update_finding(eng["id"], item["fingerprint"], status="validated")
            else:
                inconclusive += 1
                self.store.update_finding(eng["id"], item["fingerprint"],
                                          status="inconclusive")
        self.store.event(eng["id"], "validation.applied",
                         {"proven": proven, "inconclusive": inconclusive})
        return {"validated": proven, "inconclusive": inconclusive}

    def _tool_context(self, eng: dict, scope: Scope, task: dict) -> dict[str, Any]:
        assets = self.store.assets_for(eng["id"])
        open_ports = sorted({a["port"] for a in assets
                             if a["port"] and a["service"] not in {"path", "hostname"}})
        template_ids: list[str] = []
        if task["kind"] == "nuclei_validate":
            fp = task["payload"].get("fingerprint")
            finding = self.store.finding_by_fingerprint(eng["id"], fp) if fp else None
            if finding and finding.get("template_id"):
                template_ids = [finding["template_id"]]
            elif task["payload"].get("target"):
                # The planner may name a location instead of a fingerprint; it
                # still has to resolve to a template id we actually observed.
                target = task["payload"]["target"]
                for candidate in self.store.findings_for(eng["id"]):
                    if candidate.get("template_id") and target in (
                            candidate.get("location") or ""):
                        template_ids = [candidate["template_id"]]
                        break
        return {
            "scope": scope,
            "ports": list(scope.allowed_ports),
            "open_ports": open_ports,
            "wordlist": str(self.wordlist) if self.wordlist.exists() else "",
            "template_ids": template_ids,
            "config": eng.get("config") or {},
        }

    # ---- ingestion ----------------------------------------------------
    def _ingest(self, eng: dict, observations: list[Any], result: ExecutionResult,
                call: ToolCall) -> None:
        eid = eng["id"]
        for obs in observations:
            data = obs.data
            if obs.type == "service":
                self.store.upsert_asset(eid, call.target, data["host"], data["port"],
                                        data.get("service", ""), data.get("product", ""),
                                        data.get("version", ""), status="open")
            elif obs.type == "url":
                parts = urlsplit(data["url"])
                self.store.upsert_asset(
                    eid, data["url"], parts.hostname or data["url"],
                    parts.port or (443 if parts.scheme == "https" else 80),
                    "http", data.get("server", ""), "",
                    status=f"{data.get('status')} {data.get('title', '')}".strip(),
                )
                self.store.add_memory("tech", (parts.hostname or "") + ":tech",
                                      json.dumps(data.get("tech") or []), eid)
            elif obs.type == "host":
                self.store.upsert_asset(eid, data["host"], data["host"], None,
                                        "hostname", "", "", status=data.get("source", ""))
            elif obs.type == "finding":
                self._ingest_finding(eng, data, result, call)
            elif obs.type == "path":
                if data.get("status") in {200, 401, 403}:
                    fp = fingerprint("path", data["url"])
                    self.store.upsert_finding(
                        eid, fp, f"Discovered path {data['url']}", "info",
                        data["url"], f"Content discovery returned HTTP {data['status']} "
                        f"({data.get('length')} bytes).", status="candidate",
                        location=data["url"], evidence_ids=[result.evidence_id],
                        source_tool="ffuf",
                    )
            elif obs.type == "auth":
                fp = fingerprint("auth", data["url"], data["username"])
                title = f"Valid credentials for {data['url']}"
                desc = (f"Login with operator-supplied credentials for user "
                        f"'{data['username']}' succeeded (HTTP {data['status']}).")
                self.store.upsert_finding(
                    eid, fp, title, "critical" if data["accepted"] else "info",
                    data["url"], desc,
                    status="validated" if data["accepted"] else "inconclusive",
                    location=data["url"], evidence_ids=[data["evidence_id"]],
                    reproduction=[f"POST {data['url']} with the reported credentials",
                                  f"Observed HTTP {data['status']} and authenticated content"],
                    source_tool="authcheck",
                )
            elif obs.type == "tls":
                if data.get("weak_protocols"):
                    fp = fingerprint("tls", data["host"], str(data["port"]))
                    self.store.upsert_finding(
                        eid, fp, "Weak TLS protocol enabled", "medium",
                        f"{data['host']}:{data['port']}",
                        "Negotiable legacy protocols: " + ", ".join(data["weak_protocols"]),
                        status="candidate", location=f"{data['host']}:{data['port']}",
                        evidence_ids=[result.evidence_id], source_tool="sslscan",
                    )

    def _ingest_finding(self, eng: dict, data: dict, result: ExecutionResult,
                        call: ToolCall) -> None:
        location = data.get("location") or call.target
        fp = fingerprint("nuclei", data.get("template_id", ""), location)
        reproduction = []
        if data.get("curl_command"):
            reproduction.append(f"Replay: {data['curl_command']}")
        if data.get("extracted"):
            reproduction.append("Matched data: " + ", ".join(
                str(x) for x in data["extracted"][:5]))
        reproduction.append(f"Evidence file: {result.evidence_path}")
        self.store.upsert_finding(
            eng["id"], fp, data.get("title") or "Unnamed template match",
            data.get("severity", "info"), location, data.get("description", ""),
            status="validated" if data.get("confirmed") else "candidate",
            cvss=data.get("cvss"), cve=data.get("cve", ""), location=location,
            reproduction=reproduction, evidence_ids=[result.evidence_id],
            source_tool=data.get("source_tool", "nuclei"),
            template_id=data.get("template_id", ""),
        )

    # ---- LLM agent tasks ---------------------------------------------
    def _floor_plan(self, eng: dict, scope: Scope) -> dict[str, Any]:
        """Deterministic coverage floor, used only when the planner returns nothing.

        This is a safety net, not the campaign path: every use is logged as
        `plan.floor` so it is visible in the event stream and the audit trail.
        Without it a weak local model could end a campaign having done nothing,
        which would look like a clean result.
        """
        eid = eng["id"]
        actions = self.store.actions_for(eid)
        findings = self.store.findings_for(eid)
        ran = {a["tool"] for a in actions if a["decision"] == "allowed"}
        finished = {t["kind"] for t in self.store.tasks_for(eid)
                    if t["state"] in {"done", "failed"}}
        urls = [r.value for r in scope.allow if r.kind == "url"]
        hosts = [r.value for r in scope.allow if r.kind in {"ip", "domain"}]
        domains = [r.value for r in scope.allow if r.kind == "domain"]

        def task(agent: str, kind: str, target: str = "") -> dict[str, Any]:
            return {"agent": agent, "kind": kind, "target": target,
                    "reason": "fallback coverage"}

        tasks: list[dict[str, Any]] = []
        if not ran:
            if domains:
                tasks.append(task("recon", "subfinder", domains[0]))
            if hosts:
                tasks.append(task("enum", "nmap", hosts[0]))
            tasks.extend(task("recon", "httpx", url) for url in urls[:2])
        elif "nuclei" not in ran:
            tasks = [task("analysis", "nuclei", url) for url in urls[:2]] or (
                [task("analysis", "nuclei", hosts[0])] if hosts else [])
        elif "ffuf" not in ran and urls:
            tasks = [task("enum", "ffuf", urls[0])]
        elif findings and "triage" not in finished:
            tasks = [task("triage", "triage")]
        elif findings and "validation" not in finished:
            tasks = [task("validation", "validation")]
        elif "report" not in finished:
            tasks = [task("report", "report")]

        return {"reasoning": "deterministic coverage floor", "tasks": tasks[:4],
                "done": not tasks}

    async def _triage(self, eng: dict) -> dict[str, Any]:
        candidates = [f for f in self.store.findings_for(eng["id"])
                      if f["status"] == "candidate"
                      # Path discoveries are observations. Sending them to triage
                      # invites invented titles and severities for a reachable URL.
                      and f["source_tool"] != "ffuf"]
        if not candidates:
            return {"skipped": "no candidates"}
        payload = [{
            "fingerprint": f["fingerprint"], "title": f["title"],
            "severity": f["severity"], "asset": f["asset"], "location": f["location"],
            "source_tool": f["source_tool"], "template_id": f.get("template_id", ""),
        } for f in candidates[:24]]

        # Small batches: a local model on CPU times out on a single large review,
        # and a failed batch must not discard the batches that already succeeded.
        applied = 0
        errors = 0
        batch_size = 3
        for start in range(0, len(payload), batch_size):
            batch = payload[start:start + batch_size]
            try:
                reviews = await self._agents["triage"].review(batch)
            except LLMError as exc:
                errors += 1
                self.store.event(eng["id"], "triage.error",
                                 {"batch": start // batch_size, "error": str(exc)[:300]})
                reviews = _fallback_triage(batch)
            for review in reviews:
                if not self.store.finding_by_fingerprint(eng["id"], review["fingerprint"]):
                    continue
                # Only the validation step may declare a finding proven. Triage
                # classifying evidence as convincing is not proof.
                if review["status"] == "validated":
                    review["status"] = "candidate"
                self.store.update_finding(
                    eng["id"], review["fingerprint"],
                    title=review["title"] or None, severity=review["severity"],
                    cvss=review["cvss"], status=review["status"],
                    description=review["description"] or None,
                    remediation=review["remediation"] or None,
                )
                applied += 1
        self.store.event(eng["id"], "triage.applied", {"count": applied})
        return {"triaged": applied, "errors": errors}

    async def _impact(self, eng: dict) -> dict[str, Any]:
        """Gated post-exploitation: one authenticated read, only after approval."""
        spec = (eng.get("config") or {}).get("impact") or {}
        if not spec:
            return {"skipped": "no impact spec configured"}
        origin = impact.origin_of(str(spec.get("login_url") or ""))
        try:
            result = await impact.demonstrate_access(self.runtime, eng, spec)
        except MissingSecret as exc:
            self.store.event(eng["id"], "secrets.missing", {"error": str(exc)[:300]})
            return {"error": str(exc), "skipped": "credential reference unresolved"}
        finally:
            # One approval authorizes one operation (which may be several
            # requests), and it is spent when the operation ends — pass or fail.
            approval = self.store.approved_for(eng["id"], impact.PROBE, origin)
            if approval:
                self.store.consume_approval(approval["id"])
                self.store.event(eng["id"], "approval.consumed",
                                 {"approval_id": approval["id"], "target": origin})
        if result.get("denied"):
            return result
        if result.get("confirmed"):
            fp = fingerprint("impact", result.get("protected_url", ""),
                             result.get("username", ""))
            self.store.upsert_finding(
                eng["id"], fp,
                f"Authenticated access to {result.get('protected_url')}", "high",
                result.get("protected_url", ""),
                f"Operator-supplied credentials authenticate and reach "
                f"{result.get('protected_url')} without further authorization checks. "
                f"Signed-in content was returned in the response.",
                status="validated", location=result.get("protected_url", ""),
                evidence_ids=result.get("evidence_ids", []),
                reproduction=[f"POST {result.get('login_url')} with the reported credentials",
                              f"GET {result.get('protected_url')} with the session cookie"],
                source_tool="impact_probe",
            )
        self.store.event(eng["id"], "impact.result",
                         {"confirmed": bool(result.get("confirmed")),
                          "reason": result.get("reason", "")})
        return result

    async def _report(self, eng: dict, scope: Scope) -> dict[str, Any]:
        findings = [f for f in self.store.findings_for(eng["id"])
                    if f["status"] in {"validated", "candidate"}]
        # A report is not "done" while candidates sit unproven: prove them first,
        # then report. The planner may ask for the report too early; the engine owns
        # this ordering so "validated" in a report means it was validated.
        tasks = self.store.tasks_for(eng["id"])
        # Proof can come from a validation task, from a validating tool
        # (nuclei_validate, authcheck, impact), or already be recorded on a
        # finding. Any of those means validation ran; only a campaign that has
        # done none of them is told to prove things first.
        proving = {"validation", "nuclei_validate", "authcheck", "impact"}
        validation_ran = (any(t["kind"] in proving and t["state"] == "done" for t in tasks)
                          or any(f["status"] == "validated" for f in findings))
        candidates = [f for f in findings if f["status"] == "candidate"
                      and not (f["source_tool"] == "ffuf" and f["severity"] == "info")]
        if candidates and not validation_ran:
            self.store.add_task(eng["id"], "validation", "validation", "validation",
                                {"reason": "report deferred until candidates are proven"})
            self.store.event(eng["id"], "report.deferred",
                             {"candidates": len(candidates)})
            return {"deferred": "validation", "candidates": len(candidates)}
        meta = self._meta(eng)
        try:
            summary = await self._agents["report"].write(findings, {
                "name": eng["name"], "autonomy": eng["autonomy"],
                "scope": scope.as_dict(),
                "assets": self.store.assets_for(eng["id"])[:20],
            })
        except LLMError as exc:
            summary = {
                "executive_summary": "Executive summary could not be generated "
                                     f"({exc}). The findings below are unaffected.",
                "remediation": {},
            }
        if not (summary.get("executive_summary") or "").strip():
            summary["executive_summary"] = _count_summary(findings)
        meta["model"] = self.llm.model or self.llm.provider
        directory = self.settings.home / "reports" / eng["id"]
        paths = report.write_bundle(directory, findings,
                                    dict(eng, model=meta.get("model", "")), summary, meta)
        self.store.event(eng["id"], "report.written",
                         {k: str(v) for k, v in paths.items()})
        self.store.set_status(eng["id"], "completed")
        return {"report": {k: str(v) for k, v in paths.items()},
                "findings": len(findings)}

    def _meta(self, eng: dict) -> dict[str, Any]:
        actions = self.store.actions_for(eng["id"])
        evidence = self.store.evidence_for(eng["id"])
        ok, message = self.audit.verify()
        events = self.store.events_since(eng["id"], 0, 5000)
        usage = []
        for event in events:
            if event["type"] == "llm.usage":
                try:
                    usage.append(json.loads(event["payload_json"]))
                except json.JSONDecodeError:
                    continue
        stamps = sorted(e["ts"] for e in events if e.get("ts"))
        seconds = 0
        if len(stamps) > 1:
            try:
                seconds = int((datetime.fromisoformat(stamps[-1])
                               - datetime.fromisoformat(stamps[0])).total_seconds())
            except ValueError:
                seconds = 0
        tool_seconds = 0.0
        for action in actions:
            try:
                start = datetime.fromisoformat(action["started_at"])
                end = datetime.fromisoformat(action["finished_at"] or action["started_at"])
                tool_seconds += max(0.0, (end - start).total_seconds())
            except (ValueError, TypeError):
                continue
        return {
            "generated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "actions_allowed": sum(1 for a in actions if a["decision"] == "allowed"),
            "actions_denied": sum(1 for a in actions if a["decision"] == "denied"),
            "tools_used": sorted({a["tool"] for a in actions if a["decision"] == "allowed"}),
            "audit_status": message if ok else f"FAILED: {message}",
            "evidence_paths": {e["id"]: e["path"] for e in evidence},
            "model": self.llm.model or self.llm.provider,
            "tool_seconds": round(tool_seconds, 1),
            "campaign_seconds": seconds,
            "llm": {
                "calls": len(usage),
                "input_tokens": sum(int(u.get("in") or 0) for u in usage),
                "output_tokens": sum(int(u.get("out") or 0) for u in usage),
                "models": sorted({str(u.get("model")) for u in usage if u.get("model")}),
            },
        }

    # ---- state for prompts -------------------------------------------
    def _state(self, eng: dict, scope: Scope) -> dict[str, Any]:
        eid = eng["id"]
        assets = self.store.assets_for(eid)
        findings = self.store.findings_for(eid)
        actions = self.store.actions_for(eid)
        return {
            "engagement": {"id": eid, "name": eng["name"], "autonomy": eng["autonomy"]},
            "scope": scope.as_dict(),
            "assets": [{"host": a["host"], "port": a["port"], "service": a["service"],
                        "product": a["product"], "status": a["status"]}
                       for a in assets[:30]],
            "findings": [{"fingerprint": f["fingerprint"], "title": f["title"],
                          "severity": f["severity"], "status": f["status"],
                          "location": f["location"]} for f in findings[:30]],
            "actions": {
                "total": len(actions),
                "denied": [a["deny_reason"] for a in actions if a["decision"] == "denied"][:5],
                "tools_run": sorted({a["tool"] for a in actions
                                     if a["decision"] == "allowed"}),
            },
            "learned": self._learned(),
            "available_tools": [t["name"] for t in self.toolbox.catalog() if t["available"]],
        }

    def _learned(self) -> list[str]:
        """What earlier steps learned, in one line per tool.

        The planner gets outcomes, not raw tool output: the full observation dump
        bloats a prompt and the model cannot act on it any better.
        """
        notes: list[str] = []
        for tool in ("nuclei", "httpx", "ffuf", "nmap", "whatweb", "sslscan"):
            rows = self.store.recall("tool_result", tool, 1)
            if rows:
                try:
                    data = json.loads(rows[0])
                except ValueError:
                    continue
                # Older rows stored the count, newer ones the list.
                raw = data.get("observations")
                count = raw if isinstance(raw, int) else len(raw or [])
                notes.append(f"{tool}: {count} findings from last run, "
                             f"{data.get('denied', 0)} denied")
            for failure in self.store.recall("tool_missing", tool, 1):
                notes.append(f"{tool}: unavailable ({failure[:80]})")
        return notes[:6]

    # ---- summary -----------------------------------------------------
    def summary(self, eid: str, denial_spike: bool = False,
                steps: int = 0) -> dict[str, Any]:
        eng = self.store.get_engagement(eid) or {}
        findings = self.store.findings_for(eid)
        actions = self.store.actions_for(eid)
        evidence = self.store.evidence_for(eid)
        ok, audit_message = self.audit.verify()
        return {
            "engagement": eid,
            "status": eng.get("status"),
            "steps": steps,
            "halted_on_denial_spike": denial_spike,
            "findings": {
                "total": len(findings),
                "validated": sum(1 for f in findings if f["status"] == "validated"),
                "candidates": sum(1 for f in findings if f["status"] == "candidate"),
                "rejected": sum(1 for f in findings if f["status"] == "rejected"),
            },
            "actions": {
                "total": len(actions),
                "allowed": sum(1 for a in actions if a["decision"] == "allowed"),
                "denied": sum(1 for a in actions if a["decision"] == "denied"),
            },
            "evidence": len(evidence),
            "audit": {"ok": ok, "message": audit_message},
            "report_dir": str(self.settings.home / "reports" / eid),
        }


def _count_summary(findings: list[dict]) -> str:
    """Factual summary built from the findings table, used when the model is silent."""
    validated = [f for f in findings if f["status"] == "validated"]
    if not validated:
        return ("No finding was validated during this engagement. Any candidates listed "
                "below are unproven and should be reviewed by an operator.")
    counts = {sev: sum(1 for f in validated if f["severity"] == sev)
              for sev in ("critical", "high", "medium", "low")}
    parts = [f"{count} {sev}" for sev, count in counts.items() if count]
    top = ", ".join(sorted({f["title"] for f in validated
                            if f["severity"] in {"critical", "high"}}))
    return (f"{len(validated)} finding(s) were validated with recorded evidence "
            f"({', '.join(parts)}). " + (f"The highest-impact issues: {top}. " if top else "")
            + "Each finding below links to the tool output that proves it.")


def _fallback_triage(batch: list[dict]) -> list[dict]:
    """Keep the tool's own severity when the model cannot review a batch.

    This invents nothing: severity comes from the scanner that produced the
    candidate, and discovered paths are demoted to info because a reachable path
    is not itself a vulnerability.
    """
    out = []
    for cand in batch:
        severity = cand.get("severity") if cand.get("severity") in {
            "critical", "high", "medium", "low", "info"} else "info"
        if cand.get("source_tool") == "ffuf":
            severity = "info"
        out.append({
            "fingerprint": cand["fingerprint"],
            "title": cand.get("title", ""),
            "severity": severity,
            "cvss": None,
            "status": "candidate",
            "description": "",
            "remediation": "",
        })
    return out


def _fallback_validations(candidates: list[dict], auth_spec: dict | None) -> list[dict]:
    """Deterministic validation plan for candidates the model left unplanned.

    Safe PoCs are code, not model output: if the planner stays silent, the
    platform still proves what it can rather than leaving candidates unexamined.
    """
    out: list[dict] = []
    for cand in candidates:
        location = (cand.get("location") or "").strip()
        if not location.startswith(("http://", "https://")):
            continue
        template = (cand.get("template_id") or "").strip()
        if template and cand.get("source_tool") == "nuclei":
            out.append({"fingerprint": cand["fingerprint"], "method": "nuclei_validate",
                        "template_ids": [template], "url": location,
                        "note": "deterministic re-run"})
        elif auth_spec and location.rstrip("/") == str(auth_spec.get("url", "")).rstrip("/"):
            out.append({"fingerprint": cand["fingerprint"], "method": "authcheck",
                        "template_ids": [], "url": location,
                        "note": "deterministic credential check"})
        else:
            out.append({"fingerprint": cand["fingerprint"], "method": "http_probe",
                        "template_ids": [], "url": location,
                        "note": "deterministic exposure re-fetch"})
    return out


def _exposure_marker(finding: dict) -> str:
    """A string that must still be served for the exposure to be real."""
    text = f"{finding.get('template_id', '')} {finding.get('title', '')}".lower()
    if "env" in text:
        return "DB_PASSWORD"
    if "git" in text:
        return "[core]"
    if "backup" in text or "zip" in text:
        return "PK"
    if "phpinfo" in text:
        return "PHP Version"
    return ""