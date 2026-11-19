"""Findings from the self-review in docs/SECURITY-REVIEW.md, pinned as tests."""

from __future__ import annotations

import pytest

from redfox.models import Scope, ScopeError, parse_target
from redfox.runtime import MAX_OUTPUT_BYTES, _cap_output


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