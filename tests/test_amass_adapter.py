"""Amass adapter tests."""

from __future__ import annotations

from redfox.adapters.amass import AmassAdapter
from redfox.models import Decision, ExecutionResult, Target

AMASS_JSON = """\
{"name":"www.example.com","domain":"example.com","addresses":[{"ip":"93.184.216.34","cidr":"93.184.216.0/24","asn":15133,"desc":"EDGECAST"}],"tag":"cert","sources":["crtsh","hackertarget"]}
{"name":"mail.example.com","domain":"example.com","addresses":[{"ip":"93.184.216.35"}],"tag":"dns","sources":["crtsh"]}
{"name":"dev.example.com","domain":"example.com","addresses":[],"tag":"cert","sources":["otx","crtsh"]}
"""


def result(text: str) -> ExecutionResult:
    return ExecutionResult(action_id="act_test", decision=Decision(True, "test"),
                           exit_code=0, stdout=text, evidence_path="fixture")


def test_parse_json_lines() -> None:
    obs = AmassAdapter().parse(result("[output-file]\n" + AMASS_JSON))
    assert [o.data["host"] for o in obs] == ["www.example.com", "mail.example.com", "dev.example.com"]
    assert all(o.type == "host" and o.data["source"] == "amass" for o in obs)


def test_parse_accepts_plain_lines_but_skips_marker() -> None:
    obs = AmassAdapter().parse(result("plain.example.com\n[output-file]\n"))
    assert [o.data["host"] for o in obs] == ["plain.example.com"]


def test_parse_ignores_garbage_and_empty() -> None:
    assert AmassAdapter().parse(result("")) == []
    assert AmassAdapter().parse(result("{not json}\n\nrandom chatter here\n")) == []


def test_plan_shapes() -> None:
    adapter = AmassAdapter()
    assert list(adapter.plan(Target("ip", "10.0.0.1"), {})) == []
    calls = list(adapter.plan(Target("domain", "example.com"), {}))
    assert len(calls) == 1
    assert "{out}" in calls[0].argv and "-json" in calls[0].argv
    assert calls[0].timeout_s == 600


def test_describe() -> None:
    adapter = AmassAdapter()
    assert adapter.risk == "passive"
    assert adapter.describe()["name"] == "amass"