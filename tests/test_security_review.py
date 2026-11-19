"""Findings from the self-review in docs/SECURITY-REVIEW.md, pinned as tests."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

import redfox.runtime as runtime_module
from redfox.audit import AuditLog
from redfox.config import Settings
from redfox.db import Store
from redfox.models import Scope, ScopeError, parse_target
from redfox.policy import PolicyEnforcementPoint
from redfox.runtime import MAX_OUTPUT_BYTES, ToolRuntime, _cap_output


@pytest.mark.parametrize("hostile", [
    "-oN /tmp/owned",
    "-iL /etc/passwd",
    "example.com -oN /tmp/x",
    "example.com;cat /etc/passwd",
    "example.com|whoami",
    "$(id).example.com",
    "example.com`id`",
    "-",
])
def test_targets_that_could_be_read_as_options_are_refused(hostile: str) -> None:
    with pytest.raises(ScopeError):
        parse_target(hostile)


@pytest.mark.parametrize("hostile", [
    "http://-oN/x",
    "http://example.com a/x",
    "http://exa<mp>le.com/",
])
def test_urls_with_hostile_hosts_are_refused(hostile: str) -> None:
    with pytest.raises(ScopeError):
        parse_target(hostile)


def test_scope_rules_refuse_a_leading_dash() -> None:
    with pytest.raises(ScopeError):
        Scope.from_dict({"allow": [{"kind": "domain", "value": "-on.example.com"}]})


def test_ordinary_targets_still_parse() -> None:
    assert parse_target("127.0.0.1").kind == "ip"
    assert parse_target("app.lab.internal").host == "app.lab.internal"
    assert parse_target("http://127.0.0.1:8080/product?id=1").port == 8080
    assert parse_target("localhost").host == "localhost"


def test_hostname_with_port_and_path_is_not_confused_for_a_domain() -> None:
    target = parse_target("lab.internal:8080/product")
    assert target.host == "lab.internal" and target.port == 8080


def test_output_capture_is_capped() -> None:
    small = _cap_output(b"hello")
    assert small == "hello" and "truncated" not in small

    big = _cap_output(b"x" * (MAX_OUTPUT_BYTES + 10))
    assert "truncated" in big
    assert len(big) < MAX_OUTPUT_BYTES + 200


def test_truncated_output_is_still_redacted() -> None:
    leak = b"Authorization: Bearer abc123\n" + b"y" * (MAX_OUTPUT_BYTES + 10)
    assert "abc123" not in _cap_output(leak)


def test_a_same_named_binary_on_path_is_not_accepted(monkeypatch, tmp_path) -> None:
    """'httpx' is also the CLI of the Python httpx library, and it was trusted."""
    import dataclasses

    base = Settings.load(home=tmp_path / "home")
    # tools_dir points at the repo checkout; make a copy that has none, so
    # resolution has to fall through to PATH.
    settings = dataclasses.replace(base, tools_dir=tmp_path / "no-tools")
    runtime = ToolRuntime(settings, Store(settings.db_path),
                          AuditLog(settings.audit_path),
                          PolicyEnforcementPoint(settings))
    impostor = tmp_path / "httpx"
    monkeypatch.setattr(runtime_module.shutil, "which", lambda name: str(impostor))
    monkeypatch.setattr(runtime_module.subprocess, "run",
                        lambda *a, **k: SimpleNamespace(stdout="httpx, version 0.27.0",
                                                        stderr=""))
    with pytest.raises(runtime_module.ToolNotFound):
        runtime.resolve_binary("httpx")