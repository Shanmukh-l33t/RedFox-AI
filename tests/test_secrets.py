"""Credential references and what is allowed to leave the process."""

from __future__ import annotations

import pytest

from redfox import secrets
from redfox.adapters.auth import AuthCheck


def test_literal_values_pass_through() -> None:
    assert secrets.resolve("admin") == "admin"
    assert secrets.resolve("") == ""
    assert secrets.resolve(None) == ""


def test_reference_reads_environment(monkeypatch) -> None:
    monkeypatch.setenv("LAB_ADMIN_PASSWORD", "s3cret-value")
    assert secrets.resolve("${LAB_ADMIN_PASSWORD}") == "s3cret-value"


def test_missing_reference_is_an_error_not_a_blank(monkeypatch) -> None:
    monkeypatch.delenv("NOT_SET_ANYWHERE", raising=False)
    with pytest.raises(secrets.MissingSecret):
        secrets.resolve("${NOT_SET_ANYWHERE}")


def test_partial_reference_is_not_substituted() -> None:
    # Only a whole-value reference is a reference; anything else is literal.
    assert secrets.resolve("prefix-${VAR}") == "prefix-${VAR}"


def test_resolve_credential(monkeypatch) -> None:
    monkeypatch.setenv("U", "alice")
    monkeypatch.setenv("P", "hunter2")
    cred = secrets.resolve_credential({"username": "${U}", "password": "${P}"})
    assert cred == {"username": "alice", "password": "hunter2"}


def test_redacted_strips_every_credential_shape() -> None:
    spec = {
        "url": "https://app.test/login",
        "username_field": "user",
        "max_attempts": 3,
        "credentials": [{"username": "admin", "password": "hunter2"}],
        "passwords": ["hunter2"],
        "usernames": ["admin"],
    }
    safe = secrets.redacted(spec)
    assert safe["url"] == "https://app.test/login"
    assert safe["username_field"] == "user"
    assert safe["max_attempts"] == 3
    assert safe["credentials"] == [{"username": "<redacted>", "password": "<redacted>"}]
    assert "passwords" not in safe and "usernames" not in safe
    assert "hunter2" not in str(safe)
    assert "admin" not in str(safe["credentials"])


def test_auth_plan_never_contains_the_literal_secret(monkeypatch) -> None:
    monkeypatch.setenv("LAB_ADMIN_PASSWORD", "s3cret-value")
    spec = {"credentials": [{"username": "admin",
                             "password": "${LAB_ADMIN_PASSWORD}"}],
            "username_field": "username", "password_field": "password"}
    calls = AuthCheck().plan("https://app.test/login", spec)
    assert calls[0].data["password"] == "s3cret-value"
    # The call's recorded surface — tool, target, reason — carries no secret.
    assert "s3cret-value" not in calls[0].reason
    assert "s3cret-value" not in calls[0].target


def test_auth_plan_with_unset_reference_raises(monkeypatch) -> None:
    monkeypatch.delenv("MISSING_PW", raising=False)
    spec = {"credentials": [{"username": "admin", "password": "${MISSING_PW}"}]}
    with pytest.raises(secrets.MissingSecret):
        AuthCheck().plan("https://app.test/login", spec)