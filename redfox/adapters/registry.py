"""Adapter registry. Adding a tool means adding one class here."""

from __future__ import annotations

from typing import Any

from .auth import AuthCheck
from .amass import AmassAdapter
from .base import ToolAdapter
from .discovery import SubfinderAdapter
from .network import NmapAdapter, SslscanAdapter
from .web import FfufAdapter, HttpxAdapter, NucleiAdapter, WhatwebAdapter


def build_adapters() -> dict[str, ToolAdapter]:
    adapters: list[ToolAdapter] = [
        AmassAdapter(),
        SubfinderAdapter(),
        HttpxAdapter(),
        NmapAdapter(),
        NucleiAdapter(validate=False),
        NucleiAdapter(validate=True),
        FfufAdapter(),
        WhatwebAdapter(),
        SslscanAdapter(),
    ]
    return {a.name: a for a in adapters}


class ToolBox:
    """Adapters plus the one runtime that can act."""

    def __init__(self, runtime: Any) -> None:
        self.runtime = runtime
        self.adapters = build_adapters()
        self.auth = AuthCheck()

    def available(self) -> dict[str, bool]:
        return {name: a.available(self.runtime) for name, a in self.adapters.items()}

    def get(self, name: str) -> ToolAdapter | None:
        return self.adapters.get(name)

    def catalog(self) -> list[dict[str, Any]]:
        available = self.available()
        out = []
        for name, adapter in self.adapters.items():
            entry = adapter.describe()
            entry["available"] = available.get(name, False)
            out.append(entry)
        entry = {
            "name": self.auth.name,
            "binary": "",
            "risk": self.auth.risk,
            "phases": ["validation"],
            "summary": self.auth.summary,
            "available": True,
        }
        out.append(entry)
        return out

    def catalog_text(self) -> str:
        lines = []
        for entry in self.catalog():
            flag = "" if entry["available"] else " (NOT INSTALLED)"
            lines.append(
                f"- {entry['name']} [{entry['risk']}] phases={','.join(entry['phases'])}{flag}: "
                f"{entry['summary']}"
            )
        return "\n".join(lines)