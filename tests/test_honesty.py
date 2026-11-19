"""Honesty guards: rules that stop the pipeline from dressing up non-findings.

These exist because a small model once did exactly that — renamed a discovered
path into a "high" finding and then "confirmed" it by re-fetching the URL. Each
test pins one link in that chain shut.
"""

from __future__ import annotations

import asyncio

from redfox.engine import _exposure_marker, _fallback_triage
from redfox.models import Decision, HttpResponse
from redfox.validation import confirm_exposure, probe_sql_injection


class StubRuntime:
    """Returns canned HTTP responses; stands in for the network only."""

    def __init__(self, responses: list[tuple[int, str]]) -> None:
        self.responses = responses
        self.calls = 0

    async def execute_http(self, engagement, call, agent="validation", task_id=None):
        status, body = self.responses[min(self.calls, len(self.responses) - 1)]
        self.calls += 1
        return HttpResponse(action_id=f"act_{self.calls}", decision=Decision(True, "stub"),
                            status=status, body=body, final_url=call.url,
                            evidence_id=f"ev_{self.calls}")


def run(coro):
    return asyncio.run(coro)


def test_reachable_url_alone_is_not_confirmed() -> None:
    runtime = StubRuntime([(200, "<html>hello</html>")])
    result = run(confirm_exposure(runtime, {"id": "e"}, "http://x/", marker=""))
    assert result["confirmed"] is False
    assert "reachability alone" in result["reason"]


def test_marker_presence_confirms_exposure() -> None:
    runtime = StubRuntime([(200, "DB_PASSWORD=secret")])
    result = run(confirm_exposure(runtime, {"id": "e"}, "http://x/.env",
                                  marker="DB_PASSWORD"))
    assert result["confirmed"] is True


def test_missing_marker_is_inconclusive() -> None:
    runtime = StubRuntime([(200, "nothing here")])
    result = run(confirm_exposure(runtime, {"id": "e"}, "http://x/.env",
                                  marker="DB_PASSWORD"))
    assert result["confirmed"] is False


def test_sql_injection_needs_a_signal() -> None:
    clean = StubRuntime([(200, "<ul><li>one</li></ul>")] * 3)
    assert run(probe_sql_injection(clean, {"id": "e"},
                                   "http://x/p?id=1"))["confirmed"] is False

    erroring = StubRuntime([
        (200, "<ul><li>one</li></ul>"),
        (500, "unrecognized token: \"'\""),
        (200, "<ul><li>one</li><li>two</li></ul>"),
    ])
    result = run(probe_sql_injection(erroring, {"id": "e"}, "http://x/p?id=1"))
    assert result["confirmed"] is True
    assert "database error" in result["reason"]


def test_sql_injection_without_numeric_param_does_nothing() -> None:
    runtime = StubRuntime([(200, "ok")])
    result = run(probe_sql_injection(runtime, {"id": "e"}, "http://x/p?name=bob"))
    assert result["confirmed"] is False
    assert runtime.calls == 0


def test_fallback_triage_never_promotes_a_path() -> None:
    batch = [{"fingerprint": "fp1", "title": "Discovered path http://x/admin/",
              "severity": "high", "source_tool": "ffuf"}]
    review = _fallback_triage(batch)[0]
    assert review["severity"] == "info"
    assert review["status"] == "candidate"


def test_exposure_markers_are_specific() -> None:
    assert _exposure_marker({"title": "Git Configuration - Detect"}) == "[core]"
    assert _exposure_marker({"template_id": "generic-env"}) == "DB_PASSWORD"
    assert _exposure_marker({"title": "Discovered path /admin/"}) == ""