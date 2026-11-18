"""Safe-PoC validation.

Each check is the least intrusive test that settles the question, and every
request goes through the policy-gated HTTP path so it lands in the audit trail
with full evidence.
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from .models import HttpCall, HttpResponse, ToolCall

SQL_ERROR_MARKERS = (
    "sql syntax", "unrecognized token", "sqlite3.", "you have an error in your sql",
    "postgresql", "ora-01756", "mysql_fetch", "syntax error at or near",
    "unclosed quotation mark", "quoted string not properly terminated",
)
NUMERIC_PARAM = re.compile(r"^\d+$")


def _with_param(url: str, name: str, value: str) -> str:
    parts = urlsplit(url)
    query = [(k, value if k == name else v) for k, v in parse_qsl(parts.query, keep_blank_values=True)]
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), parts.fragment))


async def probe_sql_injection(runtime: Any, engagement: dict, url: str,
                              agent: str = "validation") -> dict[str, Any]:
    """Send a quote and a boolean payload; compare against the baseline.

    A quote that produces a database error, or an OR payload that changes the
    result set, is evidence of injection. Anything else is inconclusive — this
    never guesses.
    """
    parts = urlsplit(url)
    params = parse_qsl(parts.query, keep_blank_values=True)
    numeric = [(k, v) for k, v in params if NUMERIC_PARAM.match(v or "")]
    if not numeric:
        return {"confirmed": False, "reason": "no numeric query parameter to test",
                "evidence_ids": []}
    name, value = numeric[0]

    baseline = await runtime.execute_http(
        engagement, HttpCall(tool="http_probe", target=url, method="GET", url=url,
                             risk="validation", reason="baseline for injection check"), agent)
    quoted = await runtime.execute_http(
        engagement, HttpCall(tool="http_probe", target=url, method="GET",
                             url=_with_param(url, name, value + "'"), risk="validation",
                             reason=f"quote payload on {name}"), agent)
    boolean = await runtime.execute_http(
        engagement, HttpCall(tool="http_probe", target=url, method="GET",
                             url=_with_param(url, name, "1 OR 1=1"), risk="validation",
                             reason=f"boolean payload on {name}"), agent)

    evidence = [r.evidence_id for r in (baseline, quoted, boolean) if r.evidence_id]
    quoted_body = (quoted.body or "").lower()
    error_hit = next((m for m in SQL_ERROR_MARKERS if m in quoted_body), "")
    grew = _row_count(boolean.body) > _row_count(baseline.body)
    status_shift = boolean.status != baseline.status

    confirmed = bool(error_hit) or grew or (status_shift and boolean.status < 400)
    reason = (
        f"database error after quote ({error_hit})" if error_hit
        else "boolean payload expanded the result set" if grew
        else "response changed under boolean payload" if status_shift
        else "no injection signal"
    )
    return {
        "confirmed": confirmed,
        "reason": reason,
        "evidence_ids": evidence,
        "payloads": {"quote": _with_param(url, name, value + "'"),
                     "boolean": _with_param(url, name, "1 OR 1=1")},
    }


def _row_count(body: str) -> int:
    return (body or "").lower().count("<li>")


async def confirm_exposure(runtime: Any, engagement: dict, url: str,
                           marker: str = "", agent: str = "validation") -> dict[str, Any]:
    """Re-fetch a finding's location and confirm the exposed content is still there."""
    resp: HttpResponse = await runtime.execute_http(
        engagement, HttpCall(tool="http_probe", target=url, method="GET", url=url,
                             risk="validation", reason="reproduce reported exposure"), agent)
    body = resp.body or ""
    if marker and marker in body:
        return {"confirmed": True, "reason": f"marker '{marker}' still served",
                "evidence_ids": [resp.evidence_id]}
    if not marker and resp.status == 200 and len(body) > 0:
        return {"confirmed": True, "reason": "location still returns content",
                "evidence_ids": [resp.evidence_id]}
    return {"confirmed": False, "reason": f"HTTP {resp.status}, marker not found",
            "evidence_ids": [resp.evidence_id] if resp.evidence_id else []}


async def probe_reflection(runtime: Any, engagement: dict, url: str,
                           parameter: str, agent: str = "validation") -> dict[str, Any]:
    """Reflected-XSS proof: the exact payload must come back unescaped."""
    token = "rflx9z<svg/onload=1>"
    payload_url = _with_param(url, parameter, token)
    resp = await runtime.execute_http(
        engagement, HttpCall(tool="http_probe", target=payload_url, method="GET",
                             url=payload_url, risk="validation",
                             reason=f"reflection check on {parameter}"), agent)
    confirmed = token in (resp.body or "")
    return {"confirmed": confirmed,
            "reason": "payload reflected unescaped" if confirmed else "payload not reflected",
            "evidence_ids": [resp.evidence_id] if resp.evidence_id else []}  


def scope_probe_call(url: str) -> ToolCall:
    return ToolCall(tool="http_probe", target=url, argv=("GET", url), risk="validation",
                    reason="scope probe")