"""Adapter tests against real captured tool output.

Fixtures in tests/fixtures/ are actual runs against lab/vulnapp.py, not hand-written
samples, so a parser regression shows up here before it shows up in a report.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from redfox.adapters.discovery import SubfinderAdapter
from redfox.adapters.network import NmapAdapter, SslscanAdapter
from redfox.adapters.web import FfufAdapter, HttpxAdapter, NucleiAdapter, WhatwebAdapter
from redfox.models import Decision, ExecutionResult, Target

FIXTURES = Path(__file__).parent / "fixtures"


def result(text: str, exit_code: int = 0) -> ExecutionResult:
    return ExecutionResult(action_id="act_test", decision=Decision(True, "test"),
                           exit_code=exit_code, stdout=text, evidence_path="fixture")


def test_nmap_parses_real_scan() -> None:
    xml = (FIXTURES / "nmap_lab.xml").read_text(encoding="utf-8")
    obs = NmapAdapter().parse(result(xml))
    ports = {o.data["port"] for o in obs}
    assert ports == {8080, 8081}
    assert all(o.type == "service" for o in obs)
    assert all(o.data["host"] == "127.0.0.1" for o in obs)


def test_nmap_ignores_garbage() -> None:
    assert NmapAdapter().parse(result("no xml here")) == []


def test_httpx_parses_json_line() -> None:
    text = (FIXTURES / "httpx_lab.jsonl").read_text(encoding="utf-8")
    obs = HttpxAdapter().parse(result(text))
    assert len(obs) == 1
    assert obs[0].data["status"] == 200
    assert obs[0].data["title"] == "Portal"
    assert "labhttp" in obs[0].data["server"]


def test_nuclei_parses_findings() -> None:
    text = (FIXTURES / "nuclei_lab.jsonl").read_text(encoding="utf-8")
    obs = NucleiAdapter().parse(result(text))
    assert len(obs) == 5
    templates = {o.data["template_id"] for o in obs}
    assert "git-config" in templates
    sev = {o.data["template_id"]: o.data["severity"] for o in obs}
    assert sev["git-config"] == "medium"
    assert all(o.data["confirmed"] is False for o in obs)


def test_nuclei_validate_marks_confirmation() -> None:
    text = (FIXTURES / "nuclei_lab.jsonl").read_text(encoding="utf-8")
    obs = NucleiAdapter(validate=True).parse(result(text))
    assert all(o.data["confirmed"] for o in obs)


def test_ffuf_parses_results_file() -> None:
    text = (FIXTURES / "ffuf_lab.json").read_text(encoding="utf-8")
    obs = FfufAdapter().parse(result("[output-file]\n" + text))
    assert len(obs) == 6
    assert any(o.data["url"].endswith("/admin/") for o in obs)


def test_ffuf_without_json_returns_nothing() -> None:
    assert FfufAdapter().parse(result("compiled 96 words")) == []


def test_whatweb_parses_plugin_array() -> None:
    payload = json.dumps([{"target": "http://x/", "http_status": 200,
                           "plugins": {"Apache": {"version": ["2.4.41"]},
                                       "HTML5": {}}}])
    obs = WhatwebAdapter().parse(result(payload))
    assert len(obs) == 1
    assert "Apache/2.4.41" in obs[0].data["tech"]


def test_subfinder_accepts_json_and_plain_lines() -> None:
    text = '{"host":"a.example.com","input":"example.com","source":"crtsh"}\nb.example.com\n'
    obs = SubfinderAdapter().parse(result(text))
    hosts = {o.data["host"] for o in obs}
    assert hosts == {"a.example.com", "b.example.com"}


def test_sslscan_parses_weak_protocols() -> None:
    xml = ('<?xml version="1.0"?><document><ssltest host="h" port="443">'
           '<protocol type="ssl" enabled="0"/><protocol type="tls10" enabled="1"/>'
           '<protocol type="tls12" enabled="1"/></ssltest></document>')
    obs = SslscanAdapter().parse(result(xml))
    assert obs and obs[0].data["weak_protocols"] == ["tls10"]


# ---- plan() shapes ---------------------------------------------------------
def test_nmap_plan_stays_inside_port_spec() -> None:
    calls = list(NmapAdapter().plan(Target("ip", "127.0.0.1"), {"ports": [8080, 8081]}))
    assert len(calls) == 1
    assert "-p8080-8081" in calls[0].argv
    assert calls[0].ports == (8080, 8081)


def test_nuclei_validate_needs_template_ids() -> None:
    adapter = NucleiAdapter(validate=True)
    assert list(adapter.plan(Target("url", "127.0.0.1", "http", 8080), {})) == []
    calls = list(adapter.plan(Target("url", "127.0.0.1", "http", 8080),
                              {"template_ids": ["git-config"]}))
    assert "-id" in calls[0].argv and "git-config" in calls[0].argv


def test_ffuf_plan_needs_wordlist() -> None:
    assert list(FfufAdapter().plan(Target("url", "h", "http", 80), {})) == []
    calls = list(FfufAdapter().plan(Target("url", "h", "http", 80),
                                    {"wordlist": "/tmp/w.txt"}))
    assert "{out}" in calls[0].argv


def test_subfinder_only_for_domains() -> None:
    assert list(SubfinderAdapter().plan(Target("ip", "10.0.0.1"), {})) == []
    calls = list(SubfinderAdapter().plan(Target("domain", "example.com"), {}))
    assert calls[0].risk == "passive"


@pytest.mark.parametrize("adapter", [NmapAdapter(), HttpxAdapter(), NucleiAdapter(),
                                     FfufAdapter(), WhatwebAdapter(), SslscanAdapter()])
def test_every_adapter_declares_a_risk_class(adapter) -> None:
    assert adapter.risk in {"passive", "active", "validation", "intrusive"}
    assert adapter.describe()["name"] == adapter.name

def test_whatweb_parses_json_after_the_output_file_marker() -> None:
    """The runtime merges the log file in behind a marker that contains a '['.

    whatweb ran for the first time in CI and parsed to nothing because of it.
    """
    payload = json.dumps([
        {"target": "http://127.0.0.1:8080/", "http_status": 200,
         "plugins": {"Python": {"version": ["3.12"]}, "HTML5": {}}}
    ])
    merged = "\n[output-file]\n" + payload + "\n"
    observations = WhatwebAdapter().parse(result(merged))
    assert len(observations) == 1
    assert observations[0].data["status"] == 200
    assert "Python/3.12" in observations[0].data["tech"]
    assert "HTML5" in observations[0].data["tech"]


def test_whatweb_parses_the_console_line_when_there_is_no_json_log() -> None:
    line = ("http://127.0.0.1:8080 [200 OK] Country[RESERVED][ZZ], "
            "HTTPServer[labhttp/1.0], IP[127.0.0.1], Title[Portal]\n")
    observations = WhatwebAdapter().parse(result(line))
    assert len(observations) == 1
    assert observations[0].data["status"] == 200
    assert "HTTPServer" in observations[0].data["tech"]
    assert "127.0.0.1" not in observations[0].data["tech"]  # the IP value, not a plugin
