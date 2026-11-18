"""Safety-core tests. These are the gate: nothing scans until they pass."""

from __future__ import annotations

import asyncio
import shutil
from pathlib import Path

import pytest

from redfox.audit import AuditLog
from redfox.config import Settings
from redfox.db import Store
from redfox.models import Scope, ScopeError, ToolCall, parse_target
from redfox.policy import PolicyEnforcementPoint
from redfox.runtime import ToolRuntime


@pytest.fixture()
def settings(tmp_path: Path) -> Settings:
    return Settings.load(home=tmp_path / "home")


@pytest.fixture()
def store(settings: Settings) -> Store:
    return Store(settings.db_path)


@pytest.fixture()
def audit(settings: Settings) -> AuditLog:
    return AuditLog(settings.audit_path)


@pytest.fixture()
def policy(settings: Settings) -> PolicyEnforcementPoint:
    return PolicyEnforcementPoint(settings)


SCOPE = {"allow": ["lab.internal", "10.10.0.0/24", "http://10.10.0.9:8080"],
         "deny": ["admin.lab.internal"], "ports": "80,443,8000-8100"}


def engagement(autonomy: int = 2, lab: bool = False, auto_intrusive: bool = False) -> dict:
    return {
        "id": "eng_test",
        "autonomy": autonomy,
        "scope": SCOPE,
        "authorization": {"operator": "t", "authorization_ref": "AUTH-1",
                          "attested_at": "2026-01-01", "lab_isolated": lab},
        "config": {"auto_intrusive": auto_intrusive},
    }


def call(target: str, risk: str = "active", tool: str = "nmap", ports: tuple = ()) -> ToolCall:
    return ToolCall(tool=tool, target=target, argv=("-sV", target), risk=risk, ports=ports)


# ---- scope engine ---------------------------------------------------------
def test_subdomain_in_scope() -> None:
    scope = Scope.from_dict(SCOPE)
    ok, _ = scope.check(parse_target("app.lab.internal"))
    assert ok


def test_lookalike_domain_out_of_scope() -> None:
    scope = Scope.from_dict(SCOPE)
    ok, why = scope.check(parse_target("lab.internal.evil.com"))
    assert not ok and "not in the authorized scope" in why


def test_exclusion_beats_allow() -> None:
    scope = Scope.from_dict(SCOPE)
    ok, why = scope.check(parse_target("admin.lab.internal"))
    assert not ok and "exclusion" in why


def test_cidr_member_and_non_member() -> None:
    scope = Scope.from_dict(SCOPE)
    assert scope.check(parse_target("10.10.0.7"))[0]
    assert not scope.check(parse_target("10.10.1.7"))[0]


def test_internet_wide_scope_refused() -> None:
    with pytest.raises(ScopeError):
        Scope.from_dict({"allow": ["0.0.0.0/0"]})


def test_wildcard_scope_refused() -> None:
    with pytest.raises(ScopeError):
        Scope.from_dict({"allow": ["*.example.com"]})


def test_empty_scope_refused() -> None:
    with pytest.raises(ScopeError):
        Scope.from_dict({"allow": []})


def test_unresolvable_target_refused() -> None:
    with pytest.raises(ScopeError):
        parse_target("")


def test_ports_outside_spec_denied() -> None:
    scope = Scope.from_dict(SCOPE)
    assert scope.check_ports([80, 8080])[0]
    assert not scope.check_ports([3306])[0]


# ---- policy enforcement ---------------------------------------------------
def test_l0_blocks_active_scan(policy: PolicyEnforcementPoint) -> None:
    d = policy.check(call("app.lab.internal"), engagement(autonomy=0))
    assert not d.allowed and "exceeds autonomy" in d.reason


def test_l1_allows_active_but_not_validation(policy: PolicyEnforcementPoint) -> None:
    eng = engagement(autonomy=1)
    assert policy.check(call("app.lab.internal", "active"), eng).allowed
    d = policy.check(call("app.lab.internal", "validation"), eng)
    assert not d.allowed


def test_intrusive_requires_approval_even_at_l3(policy: PolicyEnforcementPoint) -> None:
    d = policy.check(call("app.lab.internal", "intrusive"), engagement(3, lab=True))
    assert not d.allowed and d.needs_approval


def test_intrusive_auto_allowed_at_l3_lab_when_configured(
    policy: PolicyEnforcementPoint,
) -> None:
    d = policy.check(call("app.lab.internal", "intrusive"),
                     engagement(3, lab=True, auto_intrusive=True))
    assert d.allowed


def test_out_of_scope_blocked(policy: PolicyEnforcementPoint) -> None:
    d = policy.check(call("evil.example.org"), engagement(3, lab=True, auto_intrusive=True))
    assert not d.allowed and "not in the authorized scope" in d.reason


def test_network_range_is_not_an_executable_target(policy: PolicyEnforcementPoint) -> None:
    d = policy.check(call("10.10.0.0/24"), engagement(2))
    assert not d.allowed and "expand it to hosts" in d.reason


def test_kill_switch_blocks_everything(policy: PolicyEnforcementPoint) -> None:
    policy.engage_kill()
    d = policy.check(call("app.lab.internal"), engagement(2))
    assert not d.allowed and "kill switch" in d.reason
    policy.clear_kill()
    assert policy.check(call("app.lab.internal"), engagement(2)).allowed


def test_rate_limit(policy: PolicyEnforcementPoint, settings: Settings) -> None:
    eng = engagement(2)
    outcomes = [policy.check(call(f"h{i}.lab.internal"), eng).allowed for i in range(200)]
    assert not all(outcomes), "rate limiter never engaged"


# ---- audit trail ----------------------------------------------------------
def test_audit_chain_verifies_and_detects_tampering(audit: AuditLog) -> None:
    audit.append({"engagement_id": "e", "action": "one"})
    audit.append({"engagement_id": "e", "action": "two"})
    ok, msg = audit.verify()
    assert ok, msg
    lines = audit.path.read_text(encoding="utf-8").splitlines()
    audit.path.write_text(lines[0] + "\n" + lines[1].replace("two", "three") + "\n",
                          encoding="utf-8")
    ok, msg = audit.verify()
    assert not ok and "mismatch" in msg


# ---- runtime wiring -------------------------------------------------------
def test_runtime_records_denials(settings: Settings, store: Store, audit: AuditLog,
                                 policy: PolicyEnforcementPoint) -> None:
    runtime = ToolRuntime(settings, store, audit, policy)
    eng = engagement(1)
    eid = store.create_engagement("t", eng["scope"], eng["authorization"], 1)
    eng["id"] = eid
    result = asyncio.run(runtime.execute(eng, call("evil.example.org"), "recon"))
    assert result.decision.allowed is False
    actions = store.actions_for(eid)
    assert actions and actions[0]["decision"] == "denied"
    assert audit.records(eid)


@pytest.mark.skipif(shutil.which("nmap") is None, reason="nmap not installed")
def test_runtime_executes_real_tool_and_stores_evidence(
    settings: Settings, store: Store, audit: AuditLog, policy: PolicyEnforcementPoint
) -> None:
    runtime = ToolRuntime(settings, store, audit, policy)
    eng = engagement(2)
    scope = dict(eng["scope"], allow=[*eng["scope"]["allow"], "127.0.0.1"])
    eng["scope"] = scope
    eid = store.create_engagement("t", scope, eng["authorization"], 2)
    eng["id"] = eid
    result = asyncio.run(
        runtime.execute(eng, ToolCall(tool="nmap", target="127.0.0.1",
                                      argv=("--version",), risk="active"), "recon")
    )
    assert result.exit_code == 0
    assert "nmap" in result.stdout.lower()
    assert Path(result.evidence_path).exists()
    assert result.output_sha256
    assert store.evidence_for(eid)