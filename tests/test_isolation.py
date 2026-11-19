"""Container isolation: what gets wrapped, and what refuses to run."""

from __future__ import annotations

import asyncio
import dataclasses
import sys
from pathlib import Path

import pytest

from redfox import isolation, runtime as runtime_module
from redfox.audit import AuditLog
from redfox.config import Settings
from redfox.db import Store
from redfox.models import ToolCall
from redfox.policy import PolicyEnforcementPoint
from redfox.runtime import ToolNotFound, ToolRuntime

SCOPE = {"allow": ["127.0.0.1", "http://127.0.0.1:8080"], "deny": [],
         "ports": "80,443,8080-8081"}
AUTH = {"operator": "test", "authorization_ref": "T-1", "attested_at": "2026-01-01"}


def test_the_tool_runs_in_an_image_with_only_the_evidence_dir(tmp_path) -> None:
    out = tmp_path / "evidence" / "act_1_out.json"
    argv = isolation.docker_argv(
        "nuclei", ["-u", "http://127.0.0.1:8080", "-jsonl", f"-o={out}"],
        tmp_path / "evidence", "redfox-scan")

    assert argv[:2] == ["docker", "run"]
    assert "projectdiscovery/nuclei:latest" in argv
    assert "redfox-scan" in argv
    # The host path becomes the mount, so the container writes where we read.
    assert f"-o={isolation.EVIDENCE_MOUNT}/act_1_out.json" in argv
    # The mount is the only place the host path appears; the tool's own
    # arguments must not carry it.
    after_image = argv[argv.index("projectdiscovery/nuclei:latest"):]
    assert str(tmp_path) not in " ".join(after_image)
    assert "--cap-drop" in argv and "no-new-privileges" in argv


def test_no_image_means_refusal_not_a_silent_host_run() -> None:
    # A future adapter that nobody mapped: refuse rather than fall back to host.
    with pytest.raises(isolation.IsolationUnavailable):
        isolation.docker_argv("nikto", [], Path("/tmp"), "bridge")


@pytest.fixture()
def iso_runtime(tmp_path: Path):
    base = Settings.load(home=tmp_path / "home")
    settings = dataclasses.replace(base, isolate="docker", docker_network="lab")
    store = Store(settings.db_path)
    audit = AuditLog(settings.audit_path)
    runtime = ToolRuntime(settings, store, audit, PolicyEnforcementPoint(settings))
    eid = store.create_engagement("iso", SCOPE, AUTH, 2)
    return runtime, store, store.get_engagement(eid), eid


def test_an_isolated_call_executes_through_docker(iso_runtime, monkeypatch) -> None:
    runtime, store, engagement, eid = iso_runtime
    captured = {}

    def fake(tool, args, evidence_dir, network, inputs=()):
        captured.update(tool=tool, args=args, network=network, inputs=inputs)
        return [sys.executable, "-c", "print('nuclei ran in a container')"]

    monkeypatch.setattr(runtime_module.isolation, "docker_argv", fake)
    result = asyncio.run(runtime.execute(
        engagement, ToolCall(tool="nuclei", target="http://127.0.0.1:8080",
                             argv=("-u", "http://127.0.0.1:8080"), risk="active"), "recon"))

    assert result.decision.allowed
    assert "container" in result.stdout
    assert captured["network"] == "lab"


def test_a_tool_without_an_image_fails_loudly(iso_runtime, monkeypatch) -> None:
    runtime, store, engagement, eid = iso_runtime

    def refuse(*_args, **_kwargs):
        raise isolation.IsolationUnavailable("no image for whatweb")

    monkeypatch.setattr(runtime_module.isolation, "docker_argv", refuse)
    with pytest.raises(ToolNotFound):
        asyncio.run(runtime.execute(
            engagement, ToolCall(tool="whatweb", target="http://127.0.0.1:8080",
                                 argv=("http://127.0.0.1:8080",), risk="active"), "recon"))

    events = [e for e in store.events_since(eid) if e["type"] == "isolation.no_image"]
    assert events and "whatweb" in events[0]["payload_json"]

def test_every_adapter_has_an_image() -> None:
    """Isolation must not have a hole where an adapter quietly has no image."""
    from redfox.adapters.registry import build_adapters

    missing = [name for name in build_adapters() if name not in isolation.IMAGES]
    assert missing == [], f"no container image for {missing}"


def test_the_image_map_covers_the_allowlist() -> None:
    from redfox.runtime import ALLOWED_BINARIES

    assert set(ALLOWED_BINARIES) <= set(isolation.IMAGES)


def test_nuclei_gets_the_shared_templates_volume(tmp_path) -> None:
    argv = isolation.docker_argv("nuclei", ["-u", "http://lab.internal:8080"],
                                 tmp_path, "redfox-lab")
    joined = " ".join(argv)
    assert f"{isolation.TEMPLATES_VOLUME}:{isolation.TEMPLATES_PATH}" in joined


def test_other_tools_do_not_get_the_templates_volume(tmp_path) -> None:
    argv = isolation.docker_argv("nmap", ["-p8080", "lab.internal"], tmp_path, "redfox-lab")
    assert isolation.TEMPLATES_VOLUME not in " ".join(argv)


def test_a_wordlist_is_mounted_read_only_and_its_path_rewritten(tmp_path) -> None:
    wordlist = tmp_path / "wordlists" / "common.txt"
    wordlist.parent.mkdir()
    wordlist.write_text("admin\nproduct\n", encoding="utf-8")

    inputs = ToolRuntime._container_inputs(
        ["-w", str(wordlist), "-u", "http://lab.internal:8080/FUZZ"], tmp_path / "evidence")
    assert inputs == ((str(wordlist.resolve()), "/inputs/0/common.txt"),)

    argv = isolation.docker_argv("ffuf", ["-w", str(wordlist)], tmp_path / "evidence",
                                 "redfox-lab", inputs)
    joined = " ".join(argv)
    assert "/inputs/0/common.txt" in joined
    assert f"{wordlist.parent.as_posix()}:/inputs/0:ro" in joined
    assert str(wordlist) not in " ".join(argv[argv.index("secsi/ffuf:latest"):])


def test_files_inside_the_evidence_dir_are_not_remounted(tmp_path) -> None:
    inside = tmp_path / "own.txt"
    inside.write_text("x", encoding="utf-8")
    assert ToolRuntime._container_inputs([str(inside)], tmp_path) == ()
