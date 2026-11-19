"""Credential handling.

Passwords in a scope file are a foot-gun: they end up in the repository, in a
backup, and in whatever reads the engagement record. A credential value may be
written as a reference instead:

    {"username": "admin", "password": "${LAB_ADMIN_PASSWORD}"}

The reference is what gets stored; the value is read from the environment at the
moment the request is built and never written to the database, the audit log, an
evidence file, or a model prompt.

A literal value still works — some engagements are a loopback lab — but
`redacted()` is what goes to any model, and it never contains either form of the
secret.
"""

from __future__ import annotations

import os
import re

REF = re.compile(r"^\$\{([A-Z][A-Z0-9_]*)\}$")
_CREDENTIAL_KEYS = ("credentials", "passwords", "usernames")


class MissingSecret(RuntimeError):
    """A ${VAR} reference was used but the variable is not set."""


def resolve(value: object) -> str:
    text = str(value if value is not None else "")
    match = REF.match(text)
    if not match:
        return text
    name = match.group(1)
    secret = os.environ.get(name)
    if not secret:
        raise MissingSecret(
            f"credential reference ${{{name}}} is not set in the environment; "
            "export it before running the campaign"
        )
    return secret


def resolve_credential(cred: dict) -> dict[str, str]:
    return {"username": resolve(cred.get("username", "")),
            "password": resolve(cred.get("password", ""))}


def redacted(spec: dict | None) -> dict | None:
    """A copy safe to put in a model prompt: no credential values, no references.

    The model only needs to know that a login form exists and how success is
    detected; it never needs the secret to plan.
    """
    if not spec:
        return spec
    out = {k: v for k, v in spec.items() if k not in _CREDENTIAL_KEYS}
    if spec.get("credentials"):
        out["credentials"] = [{"username": "<redacted>", "password": "<redacted>"}]
    elif spec.get("passwords"):
        out["passwords"] = ["<redacted>"]
    return out