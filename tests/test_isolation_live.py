"""A tool really running inside a container, against the lab.

Skipped unless Docker is available and REDFOX_ISOLATE=docker, so a normal
checkout and the unit suite stay fast. CI runs it with `--network host`, which is
what lets a container reach a lab on the CI machine's loopback.
"""

from __future__ import annotations

import asyncio
import dataclasses
import os
import shutil
import subprocess
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
AUTH = {"operator": "iso", "authorization_ref": "SELF-OWNED", "attested_at": "2026-01-01"}


def _docker_ready() -> bool:
    if shutil.which("docker") is None:
        return False
    try:
        return subprocess.run(["docker", "info"], capture_output=True, timeout=30).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def _lab_up() -> bool:
    try:
        with urllib.request.urlopen(LAB + "/", timeout=2) as response:
            return response.status == 200
    except (urllib.error.URLError, OSError):
        return False


pytestmark = [
    pytest.mark.skipif(not _docker_ready(), reason="docker daemon not available"),
    pytest.mark.skipif(os.environ.get("REDFOX_ISOLATE") != "docker",
                       reason="set REDFOX_ISOLATE=docker to run the isolation test"),
    pytest.mark.skipif(not _lab_up(), reason=f"lab not running on {LAB}"),
]


def test_nmap_runs_in_a_container_and_still_finds_the_port(tmp_path: Path) -> None:
    base = Settings.load(home=tmp_path / "home")
    settings = dataclasses.replace(
        base, isolate="docker",
        docker_network=os.environ.get("REDFOX_DOCKER_NETWORK", "host"))
    store = Store(settings.db_path)
    runtime = ToolRuntime(settings, store, AuditLog(settings.audit_path),
                          PolicyEnforcementPoint(settings))
    eid = store.create_engagement("iso", SCOPE, AUTH, 2)
    engagement = store.get_engagement(eid)

    adapter = ToolBox(runtime).get("nmap")
    calls = list(adapter.plan(parse_target("127.0.0.1"), {"ports": [8080]}))
    observations = []
    for call in calls:
        result = asyncio.run(runtime.execute(engagement, call, "recon"))
        assert result.decision.allowed, result.decision.reason
        assert result.exit_code == 0, result.stderr[:400]
        observations.extend(adapter.parse(result))

    assert any(o.data.get("port") == 8080 for o in observations), observations
    # Evidence was written where the runtime reads it, through the mount.
    assert Path(result.evidence_path).exists()

def test_ffuf_finds_paths_through_the_mounted_wordlist(tmp_path: Path) -> None:
    """The wordlist lives on the host; it is mounted read-only into the container.

    Without the mount ffuf stats a path it cannot see and reports nothing at all.
    """
    wordlist = Path("tools/wordlists/common.txt")
    if not wordlist.exists():
        pytest.skip("wordlist missing")

    base = Settings.load(home=tmp_path / "ffuf")
    settings = dataclasses.replace(
        base, isolate="docker",
        docker_network=os.environ.get("REDFOX_DOCKER_NETWORK", "host"))
    store = Store(settings.db_path)
    runtime = ToolRuntime(settings, store, AuditLog(settings.audit_path),
                          PolicyEnforcementPoint(settings))
    eid = store.create_engagement("iso", SCOPE, AUTH, 2)
    engagement = store.get_engagement(eid)

    adapter = ToolBox(runtime).get("ffuf")
    observations = []
    for call in adapter.plan(parse_target(LAB), {"wordlist": str(wordlist)}):
        result = asyncio.run(runtime.execute(engagement, call, "recon"))
        assert result.exit_code == 0, result.stderr[:400]
        observations.extend(adapter.parse(result))

    assert observations, "ffuf parsed nothing: is the wordlist mounted?"
