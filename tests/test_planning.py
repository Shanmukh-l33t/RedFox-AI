"""Planning, ingestion and reporting tests (no network, no model)."""

from __future__ import annotations

import json
from pathlib import Path

from redfox import report
from redfox.agents import validate_plan
from redfox.engine import fingerprint
from redfox.models import Scope

STATE = {
    "scope": {"allow": ["lab.internal", "10.10.0.0/24"], "ports": "80,443,8080"},
    "engagement": {"id": "eng_x", "autonomy": 2},
}


def test_plan_accepts_in_scope_tasks() -> None:
    plan = validate_plan({"reasoning": "start", "tasks": [
        {"agent": "recon", "kind": "httpx", "target": "lab.internal"},
        {"agent": "enum", "kind": "nmap", "target": "10.10.0.5"},
        {"agent": "triage", "kind": "triage", "target": ""},
    ]}, STATE)
    assert [t["kind"] for t in plan["tasks"]] == ["httpx", "nmap", "triage"]
    assert plan["done"] is False


def test_plan_drops_out_of_scope_targets() -> None:
    plan = validate_plan({"tasks": [
        {"agent": "enum", "kind": "nmap", "target": "evil.example.org"},
        {"agent": "enum", "kind": "nmap", "target": "8.8.8.8"},
    ]}, STATE)
    assert plan["tasks"] == []
    assert plan["done"] is True


def test_plan_drops_invented_tools() -> None:
    plan = validate_plan({"tasks": [
        {"agent": "recon", "kind": "metasploit", "target": "lab.internal"},
        {"agent": "hacker", "kind": "nmap", "target": "lab.internal"},
        {"agent": "recon", "kind": "shodan_query", "target": "lab.internal"},
    ]}, STATE)
    assert plan["tasks"] == []


def test_plan_caps_task_count() -> None:
    tasks = [{"agent": "enum", "kind": "nmap", "target": "lab.internal"}] * 9
    assert len(validate_plan({"tasks": tasks}, STATE)["tasks"]) == 4


def test_cidr_target_rejected_by_plan() -> None:
    plan = validate_plan({"tasks": [
        {"agent": "enum", "kind": "nmap", "target": "10.10.0.0/24"}]}, STATE)
    assert plan["tasks"] == []


def test_fingerprint_is_stable_and_distinct() -> None:
    a = fingerprint("nuclei", "git-config", "http://x/.git/config")
    assert a == fingerprint("nuclei", "git-config", "http://x/.git/config")
    assert a != fingerprint("nuclei", "git-config", "http://y/.git/config")


def _finding(**over) -> dict:
    base = {
        "fingerprint": "fp1", "title": "Git config exposed", "severity": "medium",
        "asset": "http://127.0.0.1:8080/.git/config", "location": "http://127.0.0.1:8080/.git/config",
        "status": "validated", "description": "Repository metadata is served.",
        "evidence_ids": ["ev_1"], "source_tool": "nuclei", "template_id": "git-config",
        "cvss": None, "reproduction": ["GET /.git/config"],
    }
    base.update(over)
    return base


def test_sarif_is_valid_and_maps_severity(tmp_path: Path) -> None:
    eng = {"name": "lab", "id": "eng_x", "autonomy": 2,
           "authorization": {"authorization_ref": "AUTH-1", "operator": "op",
                             "attested_at": "2026-01-01"},
           "scope": {"allow": ["lab.internal"]}, "created_at": "2026-01-01T00:00:00Z"}
    doc = report.sarif([_finding(), _finding(fingerprint="fp2", severity="info",
                                             title="Path discovered")], eng)
    assert doc["version"] == "2.1.0"
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "RedFox AI"
    levels = [r["level"] for r in run["results"]]
    assert levels == ["warning", "note"]
    assert run["results"][0]["properties"]["evidenceIds"] == ["ev_1"]
    json.dumps(doc)  # serialisable


def test_markdown_and_html_include_evidence(tmp_path: Path) -> None:
    eng = {"name": "lab", "id": "eng_x", "autonomy": 2, "scope": {"allow": ["lab.internal"]},
           "authorization": {"operator": "op", "authorization_ref": "AUTH-1",
                             "attested_at": "2026-01-01"}}
    meta = {"actions_allowed": 3, "actions_denied": 1, "tools_used": ["nuclei"],
            "audit_status": "5 records verified", "evidence_paths": {"ev_1": "/e/ev_1.log"}}
    summary = {"executive_summary": "One exposure was confirmed.", "remediation": {}}
    md = report.markdown([_finding()], eng, summary, meta)
    assert "Git config exposed" in md and "ev_1" in md and "Authorized testing only" in md
    html_doc = report.html([_finding()], eng, summary, meta)
    assert "Git config exposed" in html_doc and "/e/ev_1.log" in html_doc
    paths = report.write_bundle(tmp_path, [_finding()], eng, summary, meta)
    assert all(p.exists() for p in paths.values())


def test_scope_roundtrip_keeps_ports() -> None:
    scope = Scope.from_dict({"allow": ["lab.internal"], "ports": "8080-8082"})
    assert scope.as_dict()["ports"] == "8080-8082"
    assert scope.check_ports([8081])[0]