"""Real tools against the real lab.

These prove an adapter is wired to a binary rather than to a fixture. They skip,
with a reason, when the binary or the lab is absent, so a bare checkout still
runs green; CI installs the binaries and starts the lab, so there they execute.
"""

from __future__ import annotations

import asyncio
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from redfox.adapters.registry import ToolBox
from redfox.audit import AuditLog
from redfox.config import Settings
from redfox.db import Store
from redfox.models import parse_target
from redfox.policy import PolicyEnforcementPoint
from redfox.runtime import ToolRuntime

LAB = "http://127.0.0.1:8080"
SCOPE = {"allow": ["127.0.0.1", LAB], "deny": [], "ports": "80,443,8080-8081"}
AUTH = {"operator": "review", "authorization_ref": "SELF-OWNED", "attested_at": "2026-01-01"}


def _lab_up() -> bool:
    try:
        with urllib.request.urlopen(LAB + "/", timeout=2) as response:
            return response.status == 200
    except (urllib.error.URLError, OSError):
        return False


lab_running = pytest.mark.skipif(not _lab_up(), reason=f"lab target not running on {LAB}")


@pytest.fixture()
def rig(tmp_path: Path):
    settings = Settings.load(home=tmp_path / "home")
    store = Store(settings.db_path)
    runtime = ToolRuntime(settings, store, AuditLog(settings.audit_path),
                          PolicyEnforcementPoint(settings))
    eid = store.create_engagement("toolchain", SCOPE, AUTH, 2)
    engagement = store.get_engagement(eid)
    toolbox = ToolBox(runtime)

    def run(name: str, target: str, ctx: dict):
        adapter = toolbox.get(name)
        assert adapter is not None, f"no adapter registered for {name}"
        if not adapter.available(runtime):
            pytest.skip(f"{name} not installed")
        calls = list(adapter.plan(parse_target(target), ctx))
        assert calls, f"{name} planned no calls"
        observations = []
        for call in calls:
            result = asyncio.run(runtime.execute(engagement, call, "recon"))
            assert result.decision.allowed, result.decision.reason
            observations.extend(adapter.parse(result))
        return observations

    return run


@lab_running
def test_nmap_reports_the_open_lab_port(rig) -> None:
    observations = rig("nmap", "127.0.0.1", {"ports": [8080]})
    services = [o for o in observations if o.data.get("port") == 8080]
    assert services, f"nmap reported {[o.data for o in observations]}"


@lab_running
def test_httpx_reports_a_live_service(rig) -> None:
    observations = rig("httpx", LAB, {})
    statuses = [o.data.get("status") for o in observations if o.data.get("status")]
    assert statuses, observations
    assert any(str(s).startswith("2") for s in statuses)


@lab_running
def test_ffuf_finds_real_paths(rig) -> None:
    wordlist = Path("tools/wordlists/common.txt")
    if not wordlist.exists():
        pytest.skip("wordlist missing")
    observations = rig("ffuf", LAB, {"wordlist": str(wordlist.resolve())})
    urls = [str(o.data.get("url") or o.data.get("input")) for o in observations]
    # /product needs a query string, so a bare probe is not expected to match.
    # What matters here is that ffuf ran and the parser read real output.
    assert len(urls) >= 3, f"ffuf found: {urls[:400]}"
    assert any("/login" in u or "/search" in u for u in urls), urls


@lab_running
def test_nuclei_runs_against_the_lab(rig) -> None:
    observations = rig("nuclei", LAB, {})
    assert isinstance(observations, list)  # zero findings is a valid answer


@lab_running
def test_whatweb_identifies_the_service(rig) -> None:
    observations = rig("whatweb", LAB, {})
    assert observations, "whatweb produced no fingerprint"