"""Gated impact demonstration (the post-exploitation step).

This is deliberately the mildest proof that settles the question "so what?":
an operator-supplied credential authenticates to one protected page and the
response is captured. It reads; it never writes, uploads, deletes or escalates.

It declares the `intrusive` risk class, so the policy gate refuses it below L3,
files an approval request at L3, and only runs after an operator approves.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit

from .models import HttpCall

PROBE = "impact_probe"


def origin_of(url: str) -> str:
    parts = urlsplit(url)
    return f"{parts.scheme}://{parts.netloc}"


async def demonstrate_access(runtime: Any, engagement: dict, spec: dict[str, Any],
                             agent: str = "postexploit") -> dict[str, Any]:
    """Log in with the given credentials and read the protected page."""
    login_url = str(spec.get("login_url") or "").strip()
    protected = str(spec.get("protected_path") or "").strip()
    credentials = list(spec.get("credentials") or [])
    if not login_url or not protected or not credentials:
        return {"confirmed": False, "reason": "impact spec is incomplete",
                "evidence_ids": []}

    cred = credentials[0]
    origin = origin_of(login_url)
    data = {
        str(spec.get("username_field") or "username"): str(cred.get("username", "")),
        str(spec.get("password_field") or "password"): str(cred.get("password", "")),
    }

    login = await runtime.execute_http(
        engagement,
        HttpCall(tool=PROBE, target=origin, method="POST", url=login_url, data=data,
                 risk="intrusive",
                 reason=f"authorized impact check: authenticate as {cred.get('username')}"),
        agent,
    )
    if not login.decision.allowed:
        return {"confirmed": False, "denied": True, "reason": login.decision.reason,
                "needs_approval": login.decision.needs_approval, "evidence_ids": []}

    cookie = ""
    headers = {k.lower(): v for k, v in (login.headers or {}).items()}
    if "set-cookie" in headers:
        cookie = headers["set-cookie"].split(";")[0]
    if not cookie or login.status >= 400:
        return {"confirmed": False,
                "reason": f"credential not accepted for the impact check (HTTP {login.status})",
                "evidence_ids": [login.evidence_id] if login.evidence_id else []}

    target_url = origin + "/" + protected.lstrip("/")
    access = await runtime.execute_http(
        engagement,
        HttpCall(tool=PROBE, target=origin, method="GET", url=target_url,
                 headers={"Cookie": cookie}, risk="intrusive",
                 reason=f"authorized impact check: read {protected} as the authenticated user"),
        agent,
    )
    if not access.decision.allowed:
        return {"confirmed": False, "denied": True, "reason": access.decision.reason,
                "needs_approval": access.decision.needs_approval,
                "evidence_ids": [login.evidence_id] if login.evidence_id else []}

    marker = str(spec.get("success_marker") or "").strip().lower()
    body = (access.body or "").lower()
    confirmed = access.status == 200 and (marker in body if marker else True)
    evidence = [e for e in (login.evidence_id, access.evidence_id) if e]
    return {
        "confirmed": confirmed,
        "reason": (f"authenticated session read {protected} (HTTP {access.status})"
                   if confirmed else
                   f"authenticated but {protected} returned HTTP {access.status}"
                   + (" without the expected marker" if marker else "")),
        "evidence_ids": evidence,
        "login_url": login_url,
        "protected_url": target_url,
        "username": str(cred.get("username", "")),
    }