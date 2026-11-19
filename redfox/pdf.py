"""PDF report writer: A4, PDF 1.4, base-14 Helvetica.

No compression and no embedded fonts keep the output greppable and dependency
free. Pages are laid out first so the footer can say "Page N of M"; byte
offsets in the xref table come from the bytes actually written.
"""

from __future__ import annotations

import json
import pathlib
from datetime import datetime, timezone
from typing import Any

VERSION = "0.1.0"
NOTICE = "Authorized testing only. Findings are listed only where recorded evidence exists."

LEFT, RIGHT = 55.0, 540.0
PAGE_W, PAGE_H = 595, 842
TOP, BOTTOM = 787.0, 55.0
WIDTH = RIGHT - LEFT
COLS = (22, 62, 232, 112, 57)  # #, severity, title, asset, status — sums to WIDTH

# Helvetica advance widths (1/1000 em) for ASCII 0x20-0x7e, from the base-14 AFM.
_WIDTHS = tuple(int(w) for w in """
278 278 355 556 556 889 667 191 333 333 389 584 278 333 278 278
556 556 556 556 556 556 556 556 556 556 278 278 584 584 584 556
1015 667 667 722 722 667 611 778 722 278 500 667 556 833 722 778
667 778 722 667 611 722 667 944 667 667 611 278 278 278 469 556
333 556 556 500 556 556 278 556 556 222 222 500 222 833 556 556
556 556 333 500 278 556 500 722 500 500 500 334 260 334 584
""".split())

_SUBS = {
    "\u2018": "'", "\u2019": "'", "\u201c": '"', "\u201d": '"', "\u2013": "-",
    "\u2014": "-", "\u2026": "...", "\u00a0": " ", "\u2022": "-", "\u00b7": "-",
    "\u2192": "->", "\u200b": "", "\t": " ",
}


def write_pdf(path: pathlib.Path, findings: list[dict[str, Any]], engagement: dict[str, Any],
              summary: dict[str, Any], meta: dict[str, Any]) -> pathlib.Path:
    font = "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica{} /Encoding /WinAnsiEncoding >>"
    objects = ["<< /Type /Catalog /Pages 2 0 R /PageMode /UseNone >>", "",
               font.format(""), font.format("-Bold")]
    kids = []
    for content in _pages(findings, engagement, summary, meta):
        objects.append(f"<< /Length {len(content.encode('latin-1'))} >>"
                       f"\nstream\n{content}\nendstream")
        objects.append(f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {PAGE_W} {PAGE_H}] "
                       f"/Resources << /Font << /F1 3 0 R /F2 4 0 R >> >> "
                       f"/Contents {len(objects)} 0 R >>")
        kids.append(f"{len(objects)} 0 R")
    objects[1] = f"<< /Type /Pages /Kids [{' '.join(kids)}] /Count {len(kids)} >>"
    path.write_bytes(_document(objects))
    return path


def _document(objects: list[str]) -> bytes:
    out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = []
    for number, body in enumerate(objects, 1):
        offsets.append(len(out))
        out += f"{number} 0 obj\n{body}\nendobj\n".encode("latin-1")
    xref = len(out)
    out += f"xref\n0 {len(objects) + 1}\n0000000000 65535 f \n".encode("ascii")
    out += "".join(f"{offset:010d} 00000 n \n" for offset in offsets).encode("ascii")
    out += (f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\n"
            f"startxref\n{xref}\n%%EOF").encode("ascii")
    return bytes(out)


def _pages(findings: list[dict[str, Any]], engagement: dict[str, Any],
           summary: dict[str, Any], meta: dict[str, Any]) -> list[str]:
    st: dict[str, Any] = {"pages": [], "ops": [], "y": TOP}
    _new_page(st)
    auth = engagement.get("authorization") or {}
    _para(st, f"Penetration test report - {engagement.get('name') or 'engagement'}", 20, 25,
          bold=True)
    _para(st, NOTICE, 10, 14, gap=8, bold=True)
    _hairline(st)
    _para(st, "\n".join(f"{label}: {value}" for label, value in (
        ("Engagement", engagement.get("id", "")),
        ("Operator", auth.get("operator", "")),
        ("Authorization ref", auth.get("authorization_ref", "")),
        ("Attested", auth.get("attested_at", "")),
        ("Autonomy", f"L{engagement.get('autonomy', 0)}"),
        ("Scope", json.dumps(engagement.get("scope") or {})),
        ("Generated", meta.get("generated")
         or datetime.now(timezone.utc).isoformat(timespec="seconds")),
        ("Model", meta.get("model") or "n/a"),
    )), 9, 12.5)

    _para(st, "Executive summary", 14, 19, gap=14, bold=True, keep=14)
    _para(st, summary.get("executive_summary") or "No summary was produced.", 10, 14)

    counts = {s: sum(f["severity"] == s for f in findings)
              for s in ("critical", "high", "medium", "low", "info")}
    _para(st, "Findings", 14, 19, gap=14, bold=True, keep=14)
    _para(st, " - ".join(f"{k.title()} {counts[k]}" for k in counts)
          + f" - total {len(findings)}", 9, 13, gap=2)
    if st["y"] < BOTTOM + 60:
        _new_page(st)
    _row(st, ("#", "Severity", "Title", "Asset", "Status"), COLS, bold=True)
    _hairline(st, gap=0)
    for i, finding in enumerate(findings, 1):
        _row(st, (i, finding.get("severity", ""), finding.get("title", ""),
                  finding.get("asset", ""), finding.get("status", "")), COLS)
    if not findings:
        _para(st, "No findings were recorded for this engagement. Findings appear here "
                  "only when recorded evidence exists.", 10, 14, gap=6)

    paths = meta.get("evidence_paths") or {}
    for i, finding in enumerate(findings, 1):
        if st["y"] < BOTTOM + 120:
            _new_page(st)
        _para(st, f"{i}. {finding.get('title') or 'Untitled finding'}", 12, 16, gap=14,
              bold=True, keep=14)
        severity = finding.get("severity", "")
        severity += f" (CVSS {finding['cvss']})" if finding.get("cvss") else ""
        _para(st, f"Severity: {severity}  |  Status: {finding.get('status', '')}  |  "
                  f"Detected by: {finding.get('source_tool') or 'n/a'}", 9, 12.5)
        _para(st, f"Asset: {finding.get('asset', '')}\n"
                  f"Location: {finding.get('location', '')}", 9, 12.5)
        _para(st, finding.get("description") or "No description.", 10, 14, gap=6)
        if finding.get("reproduction"):
            _para(st, "Reproduction", 9, 12.5, gap=9, bold=True, keep=14)
            for n, step in enumerate(finding["reproduction"], 1):
                _para(st, f"{n}. {step}", 10, 14)
        if finding.get("evidence_ids"):
            ids = ", ".join(f"{ev}" + (f" [{paths[ev]}]" if ev in paths else "")
                            for ev in finding["evidence_ids"])
            _para(st, f"Evidence: {ids}", 9, 12.5, gap=9)
        remediation = ((summary.get("remediation") or {}).get(finding.get("fingerprint"))
                       or finding.get("remediation"))
        if remediation:
            _para(st, "Remediation", 9, 12.5, gap=9, bold=True, keep=14)
            _para(st, remediation, 10, 14)
        _hairline(st, gap=12)

    meta_line = _clip(_sanitise(
        f"Generated by RedFox AI {VERSION} - tools: "
        f"{', '.join(meta.get('tools_used') or []) or 'none'} - audit chain "
        f"{meta.get('audit_status', 'unknown')} - actions {meta.get('actions_allowed', 0)} run"
        f" / {meta.get('actions_denied', 0)} refused"), WIDTH - 80, 8)
    for n, ops in enumerate(st["pages"], 1):
        page = f"Page {n} of {len(st['pages'])}"
        ops.append(f"0.4 w 0.6 G {LEFT} 50 m {RIGHT} 50 l S")
        ops.append(f"BT /F1 8 Tf {LEFT} 36 Td ({_escape(meta_line)}) Tj ET")
        ops.append(f"BT /F1 8 Tf {RIGHT - _width(page, 8):.1f} 36 Td ({page}) Tj ET")
    return ["\n".join(page) for page in st["pages"]]


def _new_page(st: dict[str, Any]) -> None:
    st["pages"].append([])
    st["ops"] = st["pages"][-1]
    st["y"] = TOP


def _para(st: dict[str, Any], text: Any, size: float = 10, lead: float | None = None,
          gap: float = 0, bold: bool = False, keep: float = 0) -> None:
    st["y"] -= gap
    lead = lead or size * 1.4
    lines = _wrap(_sanitise(text), size, WIDTH, bold)
    # A one-line heading must not sit alone at the foot of a page.
    if len(lines) == 1 and st["y"] - lead < BOTTOM + keep:
        _new_page(st)
    for line in lines:
        if st["y"] < BOTTOM + lead:
            _new_page(st)
        st["ops"].append(f"BT /{'F2' if bold else 'F1'} {size:g} Tf {LEFT} {st['y']:.2f} "
                         f"Td ({_escape(line)}) Tj ET")
        st["y"] -= lead


def _row(st: dict[str, Any], cells: tuple, widths: tuple, size: float = 9,
         bold: bool = False) -> None:
    if st["y"] < BOTTOM + size * 1.8:
        _new_page(st)
    x = LEFT
    for text, width in zip(cells, widths):
        body = _escape(_clip(_sanitise(text), width - 4, size, bold))
        st["ops"].append(f"BT /{'F2' if bold else 'F1'} {size:g} Tf {x:.1f} "
                         f"{st['y']:.2f} Td ({body}) Tj ET")
        x += width
    st["y"] -= size * 1.8


def _hairline(st: dict[str, Any], gap: float = 4.0) -> None:
    if st["y"] < BOTTOM + 14:
        _new_page(st)
    st["y"] -= gap
    st["ops"].append(f"0.4 w 0.7 G {LEFT} {st['y']:.2f} m {RIGHT} {st['y']:.2f} l S")
    st["y"] -= 9


def _width(text: str, size: float = 10, bold: bool = False) -> float:
    # 6% conservative: an overflow at the page edge is worse than wrapping early,
    # and the base-14 width table is an approximation of the real metrics.
    units = sum(_WIDTHS[ord(ch) - 32] if 32 <= ord(ch) <= 126 else 556 for ch in text)
    return units * size / 1000.0 * (1.10 if bold else 1.0) * 1.06


def _wrap(text: str, size: float = 10, width: float = WIDTH,
          bold: bool = False) -> list[str]:
    out: list[str] = []
    for para in text.splitlines() or [""]:
        line = ""
        for word in para.split():
            trial = f"{line} {word}" if line else word
            if _width(trial, size, bold) <= width:
                line = trial
                continue
            if line:
                out.append(line)
            while _width(word, size, bold) > width:  # hard-break an unbreakable token
                cut = len(word)
                while cut > 1 and _width(word[:cut], size, bold) > width:
                    cut -= 1
                out.append(word[:cut])
                word = word[cut:]
            line = word
        out.append(line)
    return out


def _clip(text: str, width: float, size: float, bold: bool = False) -> str:
    if _width(text, size, bold) <= width:
        return text
    while text and _width(text + "..", size, bold) > width:
        text = text[:-1]
    return text + ".."


def _sanitise(text: Any) -> str:
    out = []
    for ch in str(text if text is not None else ""):
        ch = _SUBS.get(ch, ch)
        keep = ch == "\n" or 0x20 <= ord(ch) <= 0x7E or 0xA0 <= ord(ch) <= 0xFF
        out.append(ch if keep else "?")
    return "".join(out)


def _escape(text: str) -> str:
    return text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")