"""Credential testing against an explicitly configured login endpoint.

This is not a credential-stuffing engine: candidates come from the engagement
config (a short, operator-supplied list, default cap 5) and every attempt is an
ordinary HTTP request recorded in the audit trail. Attempts are capped because
repeated failures can lock out real accounts.
"""

from __future__ import annotations

from typing import Any, Iterable

from ..models import HttpCall, HttpResponse
from .base import Observation

DEFAULT_MAX_ATTEMPTS = 5
_FAILURE_MARKERS = (
    "invalid", "incorrect", "wrong password", "authentication failed",
    "login failed", "bad credentials", "unauthorized",
)
_SUCCESS_MARKERS = ("logout", "sign out", "dashboard", "welcome", "profile")


class AuthCheck:
    name = "authcheck"
    risk = "validation"
    summary = "Tests operator-supplied credentials against one configured login form."

    def plan(self, target_url: str, spec: dict[str, Any]) -> list[HttpCall]:
        candidates = list(spec.get("credentials") or [])
        if not candidates:
            usernames = list(spec.get("usernames") or [])
            passwords = list(spec.get("passwords") or [])
            candidates = [{"username": u, "password": p}
                          for u in usernames for p in passwords]
        limit = int(spec.get("max_attempts", DEFAULT_MAX_ATTEMPTS))
        calls: list[HttpCall] = []
        for cand in candidates[:limit]:
            data = {
                spec.get("username_field", "username"): str(cand.get("username", "")),
                spec.get("password_field", "password"): str(cand.get("password", "")),
            }
            calls.append(HttpCall(
                tool=self.name, target=target_url, method="POST", url=target_url,
                data=data, risk=self.risk,
                reason=f"authorized login check for user {cand.get('username', '?')}",
            ))
        return calls

    def parse(self, call: HttpCall, response: HttpResponse,
              spec: dict[str, Any]) -> Observation:
        body = (response.body or "").lower()
        success_marker = str(spec.get("success_marker") or "").lower()
        failure_marker = str(spec.get("failure_marker") or "").lower()

        if success_marker:
            accepted = success_marker in body
        else:
            accepted = any(m in body for m in _SUCCESS_MARKERS) and not any(
                m in body for m in _FAILURE_MARKERS
            )
        if failure_marker and failure_marker in body:
            accepted = False
        if response.status in {401, 403}:
            accepted = False

        username = (call.data or {}).get(spec.get("username_field", "username"), "")
        return Observation("auth", {
            "url": call.url,
            "username": username,
            "accepted": accepted,
            "status": response.status,
            "final_url": response.final_url,
            "evidence_id": response.evidence_id,
            "detail": ("credentials accepted" if accepted
                       else f"login rejected (HTTP {response.status})"),
        })


def candidate_pairs(spec: dict[str, Any]) -> Iterable[tuple[str, str]]:
    for cred in spec.get("credentials") or []:
        yield str(cred.get("username", "")), str(cred.get("password", ""))