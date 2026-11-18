"""Adapter contract.

An adapter is a pure function pair: `plan()` proposes argv, `parse()` reads
output. It never executes, never touches the network, and never imports the
runtime — the policy gate cannot be bypassed from here because there is nothing
here that can act.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable

from ..models import ExecutionResult, Scope, Target, ToolCall


@dataclass(frozen=True)
class Observation:
    """Normalised fact extracted from real tool output."""

    type: str
    data: dict[str, Any]

    def as_dict(self) -> dict[str, Any]:
        return {"type": self.type, **self.data}


class ToolAdapter:
    name: str = ""
    binary: str = ""
    risk: str = "active"
    summary: str = ""
    phases: tuple[str, ...] = ("enumeration",)

    def available(self, runtime: Any) -> bool:
        return runtime.available(self.binary)

    def plan(self, target: Target, ctx: dict[str, Any]) -> Iterable[ToolCall]:  # pragma: no cover
        raise NotImplementedError

    def parse(self, result: ExecutionResult) -> list[Observation]:  # pragma: no cover
        raise NotImplementedError

    def describe(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "binary": self.binary,
            "risk": self.risk,
            "phases": list(self.phases),
            "summary": self.summary,
        }


def ports_spec(ports: Iterable[int]) -> str:
    ordered = sorted(set(ports))
    if not ordered:
        return "80,443"
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


def base_urls(target: Target, ctx: dict[str, Any]) -> list[str]:
    """Candidate web roots for a target, restricted to the scope's ports."""
    if target.kind == "url":
        return [f"{target.scheme}://{target.host}:{target.port}"]
    scope: Scope | None = ctx.get("scope")
    ports = list(scope.allowed_ports) if scope else [80, 443]
    if ctx.get("open_ports"):
        ports = [int(p) for p in ctx["open_ports"] if p in ports] or ports
    urls: list[str] = []
    for port in ports:
        scheme = "https" if port in {443, 8443} else "http"
        urls.append(f"{scheme}://{target.host}:{port}")
    return urls