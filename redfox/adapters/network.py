"""Network-layer adapters: nmap (service discovery) and sslscan (TLS posture)."""

from __future__ import annotations

import xml.etree.ElementTree as ET
from typing import Any, Iterable

from ..models import ExecutionResult, Target, ToolCall
from .base import Observation, ToolAdapter, ports_spec


class NmapAdapter(ToolAdapter):
    name = "nmap"
    binary = "nmap"
    risk = "active"
    summary = "TCP connect scan with service/version detection against the authorized ports."
    phases = ("enumeration",)

    def plan(self, target: Target, ctx: dict[str, Any]) -> Iterable[ToolCall]:
        ports = ctx.get("ports") or [80, 443]
        spec = ports_spec(ports)
        argv = (
            "-sT", "-sV", "--version-light", "-Pn", "--open", "-T4",
            f"-p{spec}", "-oX", "-", target.host,
        )
        yield ToolCall(
            tool=self.name, target=target.key, argv=argv, risk=self.risk,
            timeout_s=600, ports=tuple(sorted(set(ports))),
            reason=f"service and version discovery on {spec}",
        )

    def parse(self, result: ExecutionResult) -> list[Observation]:
        out: list[Observation] = []
        text = result.stdout.strip()
        if not text or "<nmaprun" not in text:
            return out
        try:
            root = ET.fromstring(text)
        except ET.ParseError:
            return out
        for host in root.findall("host"):
            addr = host.find("address")
            host_ip = addr.get("addr", "") if addr is not None else ""
            for port in host.findall("./ports/port"):
                state = port.find("state")
                if state is None or state.get("state") != "open":
                    continue
                svc = port.find("service")
                out.append(Observation("service", {
                    "host": host_ip,
                    "port": int(port.get("portid", "0")),
                    "protocol": port.get("protocol", "tcp"),
                    "service": svc.get("name", "") if svc is not None else "",
                    "product": svc.get("product", "") if svc is not None else "",
                    "version": svc.get("version", "") if svc is not None else "",
                    "extra_info": svc.get("extrainfo", "") if svc is not None else "",
                }))
        return out


class SslscanAdapter(ToolAdapter):
    name = "sslscan"
    binary = "sslscan"
    risk = "active"
    summary = "TLS configuration review: protocol versions, cipher strength, certificate facts."
    phases = ("enumeration",)

    def plan(self, target: Target, ctx: dict[str, Any]) -> Iterable[ToolCall]:
        port = target.port or 443
        yield ToolCall(
            tool=self.name, target=target.key,
            argv=("--no-colour", "--xml={out}", f"{target.host}:{port}"),
            risk=self.risk, timeout_s=180, ports=(port,),
            reason="TLS configuration review",
        )

    def parse(self, result: ExecutionResult) -> list[Observation]:
        out: list[Observation] = []
        text = result.stdout.strip()
        if not text:
            return out
        start = text.find("<?xml")
        if start < 0:
            return out
        try:
            root = ET.fromstring(text[start:])
        except ET.ParseError:
            return out
        for test in root.iter("ssltest"):
            host = test.get("host", "")
            port = int(test.get("port", "443") or 443)
            protocols = []
            for proto in test.iter("protocol"):
                if proto.get("enabled") in {"1", "true"}:
                    protocols.append(proto.get("type", proto.get("version", "")))
            if protocols:
                out.append(Observation("tls", {
                    "host": host, "port": port, "protocols": protocols,
                    "weak_protocols": [p for p in protocols if p.endswith(("10", "11", "SSLv2", "SSLv3"))],
                }))
        return out