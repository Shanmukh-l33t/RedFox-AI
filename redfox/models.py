"""RedFox AI — domain model and scope parsing.

A scope is a deny-by-default allowlist. Anything that cannot be matched to an
allow rule is out of scope; anything that matches a deny rule is out of scope
even when an allow rule would match it. There is no wildcard that grants the
internet.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Any, Literal
from urllib.parse import urlsplit

ScopeKind = Literal["domain", "ip", "cidr", "url"]


class ScopeError(ValueError):
    """Raised when a scope file is malformed. Malformed scopes never load."""


@dataclass(frozen=True)
class ScopeRule:
    kind: ScopeKind
    value: str

    def describe(self) -> str:
        return f"{self.kind}:{self.value}"


def _parse_rule(raw: Any) -> ScopeRule:
    if isinstance(raw, str):
        return _parse_rule_from_string(raw)
    if not isinstance(raw, dict):
        raise ScopeError(f"scope entry must be a string or object, got {type(raw).__name__}")
    kind = str(raw.get("kind") or raw.get("type") or "").strip().lower()
    value = str(raw.get("value") or "").strip()
    if not kind or not value:
        raise ScopeError("scope entry requires 'kind' and 'value'")
    return _build_rule(kind, value)


def _parse_rule_from_string(raw: str) -> ScopeRule:
    text = raw.strip()
    if not text:
        raise ScopeError("empty scope entry")
    for kind in ("domain", "ip", "cidr", "url"):
        prefix = f"{kind}:"
        if text.startswith(prefix):
            return _build_rule(kind, text[len(prefix):])
    if text.startswith(("http://", "https://")):
        return _build_rule("url", text)
    if "/" in text:
        return _build_rule("cidr", text)
    try:
        ipaddress.ip_address(text)
        return _build_rule("ip", text)
    except ValueError:
        return _build_rule("domain", text)


def _build_rule(kind: str, value: str) -> ScopeRule:
    if kind == "domain":
        host = value.lower().strip(".")
        if any(ch in host for ch in "*?/ ") or not host:
            raise ScopeError(f"invalid or wildcard domain: {value!r}")
        if host.startswith("-"):
            raise ScopeError(f"invalid domain: {value!r}")
        if len(host.split(".")) < 2 and host != "localhost":
            raise ScopeError(f"domain must be fully qualified: {value!r}")
        return ScopeRule("domain", host)
    if kind == "ip":
        try:
            return ScopeRule("ip", str(ipaddress.ip_address(value)))
        except ValueError as exc:
            raise ScopeError(f"invalid ip: {value!r}") from exc
    if kind == "cidr":
        try:
            net = ipaddress.ip_network(value, strict=False)
        except ValueError as exc:
            raise ScopeError(f"invalid cidr: {value!r}") from exc
        if net.prefixlen == 0:
            raise ScopeError("0.0.0.0/0 is not an acceptable scope")
        return ScopeRule("cidr", str(net))
    if kind == "url":
        parts = urlsplit(value)
        if parts.scheme not in {"http", "https"} or not parts.hostname:
            raise ScopeError(f"invalid url scope: {value!r}")
        return ScopeRule("url", value)
    raise ScopeError(f"unknown scope kind: {kind!r}")


@dataclass(frozen=True)
class Target:
    """A normalised thing we might touch."""

    kind: ScopeKind
    host: str
    scheme: str = ""
    port: int | None = None
    path: str = "/"

    @property
    def key(self) -> str:
        if self.kind == "url":
            return f"{self.scheme}://{self.host}:{self.port or default_port(self.scheme)}"
        return self.host


def default_port(scheme: str) -> int:
    return 443 if scheme == "https" else 80


def parse_target(raw: str) -> Target:
    text = (raw or "").strip()
    if not text:
        raise ScopeError("empty target")
    if text.startswith(("http://", "https://")):
        parts = urlsplit(text)
        if not parts.hostname:
            raise ScopeError(f"url without host: {raw!r}")
        if not _valid_host(parts.hostname.lower()):
            raise ScopeError(f"invalid host in target: {parts.hostname!r}")
        port = parts.port or default_port(parts.scheme)
        return Target("url", parts.hostname.lower(), parts.scheme, port, parts.path or "/")
    if "/" in text:
        try:
            net = ipaddress.ip_network(text, strict=False)
            return Target("cidr", str(net))
        except ValueError:
            # Not a network: it is host:port/path written without a scheme.
            parts = urlsplit("//" + text)
            if parts.hostname and _valid_host(parts.hostname.lower()):
                return Target("url", parts.hostname.lower(), "http",
                              parts.port or default_port("http"), parts.path or "/")
            raise ScopeError(f"target is not a valid host, network or URL: {raw!r}")
    try:
        ipaddress.ip_address(text)
        return Target("ip", str(ipaddress.ip_address(text)))
    except ValueError:
        host = text.lower().strip(".")
        if not _valid_host(host):
            raise ScopeError(f"target is not a valid hostname: {raw!r}")
        return Target("domain", host)


def _domain_matches(host: str, rule: str) -> bool:
    return host == rule or host.endswith("." + rule)


HOSTNAME = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?"
                      r"(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*\.?$")


def _valid_host(host: str) -> bool:
    """Reject anything that is not a hostname.

    A target string reaches a tool as one argv item. Without this, a value like
    ``-oN /tmp/x`` would be parsed by the tool as an option rather than a host —
    argument injection that no amount of "we never use a shell" prevents.
    """
    if not host or len(host) > 253:
        return False
    if host.startswith("-") or any(ch in host for ch in " \t\r\n\"'`$;|&<>"):
        return False
    return bool(HOSTNAME.match(host))


def _rule_matches(target: Target, rule: ScopeRule) -> bool:
    if rule.kind == "domain":
        return _domain_matches(target.host, rule.value)
    if rule.kind == "ip":
        return target.kind == "ip" and target.host == rule.value
    if rule.kind == "cidr":
        if target.kind != "ip":
            return False
        return ipaddress.ip_address(target.host) in ipaddress.ip_network(rule.value)
    if rule.kind == "url":
        parts = urlsplit(rule.value)
        rule_port = parts.port or default_port(parts.scheme)
        if target.kind not in {"url", "domain", "ip"}:
            return False
        if target.kind == "url":
            if target.scheme != parts.scheme:
                return False
            if (target.port or default_port(target.scheme)) != rule_port:
                return False
            if not target.path.startswith(parts.path or "/"):
                return False
        return _domain_matches(target.host, (parts.hostname or "").lower())
    return False


def expand_ports(spec: str | list[int] | None) -> list[int]:
    """Expand "80,443,8000-8100" into a sorted list. Invalid specs raise."""
    if spec is None:
        return [80, 443]
    if isinstance(spec, list):
        ports = []
        for item in spec:
            ports.extend(expand_ports(str(item)))
        return sorted(set(ports))
    ports: set[int] = set()
    for chunk in str(spec).replace(" ", "").split(","):
        if not chunk:
            continue
        if "-" in chunk:
            lo, _, hi = chunk.partition("-")
            lo_i, hi_i = int(lo), int(hi)
            if not (0 < lo_i <= hi_i <= 65535):
                raise ScopeError(f"invalid port range: {chunk}")
            ports.update(range(lo_i, hi_i + 1))
        else:
            value = int(chunk)
            if not 0 < value <= 65535:
                raise ScopeError(f"invalid port: {chunk}")
            ports.add(value)
    if not ports:
        raise ScopeError("empty port spec")
    return sorted(ports)


@dataclass(frozen=True)
class Scope:
    allow: tuple[ScopeRule, ...]
    deny: tuple[ScopeRule, ...] = ()
    allowed_ports: tuple[int, ...] = (80, 443)

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "Scope":
        if not isinstance(raw, dict):
            raise ScopeError("scope must be an object")
        allow_raw = raw.get("allow") or raw.get("targets") or []
        deny_raw = raw.get("deny") or raw.get("exclude") or raw.get("exclusions") or []
        if not allow_raw:
            raise ScopeError("scope has no allow entries; denying by default")
        allow = tuple(_parse_rule(item) for item in allow_raw)
        deny = tuple(_parse_rule(item) for item in deny_raw)
        ports = raw.get("ports", "80,443")
        allowed_ports = tuple(expand_ports(ports))
        return cls(allow, deny, allowed_ports)

    def check(self, target: Target) -> tuple[bool, str]:
        for rule in self.deny:
            if _rule_matches(target, rule):
                return False, f"target {target.key} matches exclusion {rule.describe()}"
        for rule in self.allow:
            if _rule_matches(target, rule):
                return True, f"matched allow rule {rule.describe()}"
        return False, f"target {target.key} is not in the authorized scope"

    def check_ports(self, ports: list[int]) -> tuple[bool, str]:
        stray = [p for p in ports if p not in self.allowed_ports]
        if stray:
            shown = ", ".join(str(p) for p in stray[:10])
            return False, f"ports outside the authorized port spec: {shown}"
        return True, "ports within authorized spec"

    def as_dict(self) -> dict[str, Any]:
        return {
            "allow": [{"kind": r.kind, "value": r.value} for r in self.allow],
            "deny": [{"kind": r.kind, "value": r.value} for r in self.deny],
            "ports": _ports_to_spec(self.allowed_ports),
        }


def _ports_to_spec(ports: tuple[int, ...]) -> str:
    if not ports:
        return ""
    ordered = sorted(ports)
    parts: list[str] = []
    start = prev = ordered[0]
    for p in ordered[1:]:
        if p == prev + 1:
            prev = p
            continue
        parts.append(str(start) if start == prev else f"{start}-{prev}")
        start = prev = p
    parts.append(str(start) if start == prev else f"{start}-{prev}")
    return ",".join(parts)


@dataclass(frozen=True)
class Authorization:
    """Operator attestation. Required before an engagement can start."""

    operator: str
    authorization_ref: str
    attested_at: str
    lab_isolated: bool = False
    notes: str = ""

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "Authorization":
        if not isinstance(raw, dict):
            raise ScopeError("authorization must be an object")
        missing = [
            k
            for k in ("operator", "authorization_ref", "attested_at")
            if not str(raw.get(k) or "").strip()
        ]
        if missing:
            raise ScopeError(
                "authorization record is incomplete; missing: " + ", ".join(missing)
            )
        return cls(
            operator=str(raw["operator"]).strip(),
            authorization_ref=str(raw["authorization_ref"]).strip(),
            attested_at=str(raw["attested_at"]).strip(),
            lab_isolated=bool(raw.get("lab_isolated", False)),
            notes=str(raw.get("notes") or ""),
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "operator": self.operator,
            "authorization_ref": self.authorization_ref,
            "attested_at": self.attested_at,
            "lab_isolated": self.lab_isolated,
            "notes": self.notes,
        }


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str
    risk: str = "passive"
    needs_approval: bool = False
    via_approval: bool = False

    def as_dict(self) -> dict[str, Any]:
        return {
            "allowed": self.allowed,
            "reason": self.reason,
            "risk": self.risk,
            "needs_approval": self.needs_approval,
            "via_approval": self.via_approval,
        }


@dataclass(frozen=True)
class ToolCall:
    """What an adapter proposes. Adapters never execute; the runtime does."""

    tool: str
    target: str
    argv: tuple[str, ...]
    risk: str
    timeout_s: int = 300
    ports: tuple[int, ...] = ()
    reason: str = ""
    evidence_kind: str = "tool_output"
    meta: dict[str, Any] = field(default_factory=dict)


@dataclass
class ExecutionResult:
    action_id: str
    decision: Decision
    exit_code: int | None = None
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False
    output_sha256: str = ""
    duration_s: float = 0.0
    evidence_path: str = ""
    evidence_id: str = ""


@dataclass(frozen=True)
class HttpCall:
    """A single HTTP request proposed by an adapter (auth checks, targeted probes)."""

    tool: str
    target: str
    method: str
    url: str
    data: dict[str, str] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)
    risk: str = "validation"
    reason: str = ""


@dataclass
class HttpResponse:
    action_id: str
    decision: Decision
    status: int = 0
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""
    final_url: str = ""
    evidence_id: str = ""
    duration_s: float = 0.0
    error: str = ""