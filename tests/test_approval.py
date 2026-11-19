"""The approval loop: an intrusive action is refused, approved, then run once.

These tests cover the path the brief calls out explicitly — "never silent
execution" — from the policy decision through the runtime consuming the approval.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from redfox import impact
from redfox.audit import AuditLog
from redfox.config import Settings
from redfox.db import Store
from redfox.engine import Campaign
from redfox.models import Decision, HttpResponse, ToolCall
from redfox.policy import PolicyEnforcementPoint


@pytest.fixture()
def settings(tmp_path: Path) -> Settings:
    return Settings.load(home=tmp_path / "home")


@pytest.fixture()
def store(settings: Settings) -> Store:
    return Store(settings.db_path)


SCOPE = {"allow": ["127.0.0.1", "http://127.0.0.1:8080"], "deny": [], "ports": "8080"}


def engagement(autonomy: int = 3, lab: bool = True) -> dict:
    return {
        "id": "eng_test",
        "autonomy": autonomy,
        "scope": SCOPE,
        "authorization": {"operator": "t", "authorization_ref": "AUTH-1",
                          "attested_at": "2026-01-01", "lab_isolated": lab},
        "config": {"auto_intrusive": False,
                   "impact": {"login_url": "http://127.0.0.1:8080/login",
                              "protected_path": "/admin/",
                              "credentials": [{"username": "admin", "password": "admin"}]}},
    }


def intrusive() -> ToolCall:
    return ToolCall(tool="impact_probe", target="http://127.0.0.1:8080",
                    argv=(), risk="intrusive")


def test_intrusive_refused_without_approval(settings: Settings) -> None:
    policy = PolicyEnforcementPoint(settings)
    decision = policy.check(intrusive(), engagement())
    assert not decision.allowed and decision.needs_approval


def test_intrusive_allowed_once_approved(settings: Settings, store: Store) -> None:
    eid = store.create_engagement("t", SCOPE, engagement()["authorization"], 3)
    approval = store.request_approval(eid, {"tool": "impact_probe",
                                            "target": "http://127.0.0.1:8080"}, "test")
    store.decide_approval(approval, True, "approved by operator")

    policy = PolicyEnforcementPoint(settings)
    policy.bind_approvals(lambda tool, target: store.approved_for(eid, tool, target))
    decision = policy.check(intrusive(), dict(engagement(), id=eid))
    assert decision.allowed and decision.via_approval
    assert "operator approval" in decision.reason


def test_approval_for_other_target_does_not_unlock(settings: Settings, store: Store) -> None:
    eid = store.create_engagement("t", SCOPE, engagement()["authorization"], 3)
    approval = store.request_approval(eid, {"tool": "impact_probe",
                                            "target": "http://10.9.9.9"}, "elsewhere")
    store.decide_approval(approval, True, "different target")

    policy = PolicyEnforcementPoint(settings)
    policy.bind_approvals(lambda tool, target: store.approved_for(eid, tool, target))
    decision = policy.check(intrusive(), dict(engagement(), id=eid))
    assert not decision.allowed and decision.needs_approval


def test_denied_approval_stays_closed(settings: Settings, store: Store) -> None:
    eid = store.create_engagement("t", SCOPE, engagement()["authorization"], 3)
    approval = store.request_approval(eid, {"tool": "impact_probe",
                                            "target": "http://127.0.0.1:8080"}, "test")
    store.decide_approval(approval, False, "refused")
    policy = PolicyEnforcementPoint(settings)
    policy.bind_approvals(lambda tool, target: store.approved_for(eid, tool, target))
    assert policy.check(intrusive(), dict(engagement(), id=eid)).needs_approval


def test_consumed_approval_cannot_be_reused(settings: Settings, store: Store) -> None:
    eid = store.create_engagement("t", SCOPE, engagement()["authorization"], 3)
    approval = store.request_approval(eid, {"tool": "impact_probe",
                                            "target": "http://127.0.0.1:8080"}, "test")
    store.decide_approval(approval, True, "ok")
    store.consume_approval(approval)

    policy = PolicyEnforcementPoint(settings)
    policy.bind_approvals(lambda tool, target: store.approved_for(eid, tool, target))
    assert policy.check(intrusive(), dict(engagement(), id=eid)).needs_approval


def test_campaign_stops_and_waits_for_approval(settings: Settings, store: Store) -> None:
    eid = store.create_engagement("t", SCOPE, engagement()["authorization"], 3)
    store.request_approval(eid, {"tool": "impact_probe",
                                 "target": "http://127.0.0.1:8080"}, "needs a human")
    campaign = Campaign(settings, store, AuditLog(settings.audit_path),
                        PolicyEnforcementPoint(settings))
    summary = asyncio.run(campaign.run(eid, max_steps=5))
    assert summary["status"] == "awaiting_approval"
    assert summary["actions"]["total"] == 0  # nothing ran while waiting


# ---- the impact step itself ------------------------------------------------
class StubRuntime:
    def __init__(self, login: tuple[int, str, dict], access: tuple[int, str, dict]) -> None:
        self.login = login
        self.access = access
        self.calls: list[str] = []

    async def execute_http(self, engagement, call, agent="postexploit", task_id=None):
        self.calls.append(f"{call.method} {call.url}")
        status, body, headers = self.login if call.method == "POST" else self.access
        return HttpResponse(action_id=f"act_{len(self.calls)}",
                            decision=Decision(True, "allowed", "intrusive"),
                            status=status, body=body, headers=headers,
                            evidence_id=f"ev_{len(self.calls)}")


def test_impact_confirms_authenticated_access() -> None:
    runtime = StubRuntime((200, "ok", {"Set-Cookie": "session=abc123; Path=/"}),
                          (200, "<h1>Admin console</h1>", {}))
    result = asyncio.run(impact.demonstrate_access(
        runtime, engagement(), engagement()["config"]["impact"]))
    assert result["confirmed"] is True
    assert result["evidence_ids"] == ["ev_1", "ev_2"]
    assert runtime.calls == ["POST http://127.0.0.1:8080/login",
                             "GET http://127.0.0.1:8080/admin/"]


def test_impact_without_cookie_is_not_confirmed() -> None:
    runtime = StubRuntime((200, "ok", {}), (200, "should not be read", {}))
    result = asyncio.run(impact.demonstrate_access(
        runtime, engagement(), engagement()["config"]["impact"]))
    assert result["confirmed"] is False
    assert len(runtime.calls) == 1  # it never read the protected page


def test_impact_requires_marker_when_configured() -> None:
    spec = dict(engagement()["config"]["impact"], success_marker="admin console")
    runtime = StubRuntime((200, "ok", {"Set-Cookie": "s=1"}), (200, "<h1>nope</h1>", {}))
    assert asyncio.run(impact.demonstrate_access(runtime, engagement(), spec))[
        "confirmed"] is False

    runtime_ok = StubRuntime((200, "ok", {"Set-Cookie": "s=1"}),
                             (200, "<h1>Admin Console</h1>", {}))
    assert asyncio.run(impact.demonstrate_access(
        runtime_ok, engagement(), spec))["confirmed"] is True


def test_impact_reports_denial_without_acting() -> None:
    class Denying(StubRuntime):
        async def execute_http(self, engagement, call, agent="postexploit", task_id=None):
            self.calls.append(call.url)
            return HttpResponse(action_id="a", decision=Decision(
                False, "exceeds autonomy", "intrusive", needs_approval=True))

    runtime = Denying((200, "", {}), (200, "", {}))
    result = asyncio.run(impact.demonstrate_access(
        runtime, engagement(autonomy=2), engagement()["config"]["impact"]))
    assert result["denied"] is True and result["needs_approval"] is True