"""PDF report writer tests: file structure, xref integrity, layout (no network)."""

from __future__ import annotations

import re
from pathlib import Path

from redfox import pdf

ENG = {
    "name": "Acme lab", "id": "eng_1", "autonomy": 2,
    "scope": {"allow": ["10.10.0.5"], "ports": "8080"},
    "authorization": {"operator": "op", "authorization_ref": "AUTH-1",
                      "attested_at": "2026-01-01T00:00:00Z"},
    "created_at": "2026-01-01T00:00:00Z",
}
META = {
    "generated": "2026-01-02T03:04:05+00:00", "actions_allowed": 9, "actions_denied": 2,
    "tools_used": ["nuclei", "httpx"], "audit_status": "12 records verified",
    "model": "test-model", "evidence_paths": {"ev_2": "/e/ev_2.log"},
}
LONG_URL = ("https://10.10.0.5:8080/backups/2026/very-long-path-"
            + "segment/" * 30 + "dump.sql?token=" + "ab12" * 40)


def _title(i: int) -> str:
    return f"Backup archive db-{i}.sql ({i})"


def _esc(text: str) -> str:
    return text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def _finding(i: int) -> dict:
    return {
        "fingerprint": f"fp_{i}",
        "title": _title(i),
        "severity": ("critical", "high", "medium", "low", "info")[i % 5],
        "status": "validated",
        "asset": "10.10.0.5:8080",
        "location": LONG_URL,
        "description": ("The café portal exposes “raw” dumps — no authentication needed. "
                        "注入 payload accepted at " + LONG_URL),
        "cvss": 7.5 if i % 3 == 0 else None,
        "evidence_ids": [f"ev_{i}", f"ev_{i}_b"],
        "reproduction": ["curl -s " + LONG_URL, f"grep db-{i} dump.sql"],
        "source_tool": "nuclei",
        "template_id": "exposed-backup",
    }


def _summary(findings: list[dict], text: str = "") -> dict:
    return {
        "executive_summary": text or ("Twelve exposures were validated across the in-scope "
                                      "host; the database dumps are reachable without auth."),
        "remediation": {f["fingerprint"]: "Remove the backup directory from the web root."
                        for f in findings},
    }


def _render(tmp_path: Path, findings: list[dict]) -> bytes:
    path = pdf.write_pdf(tmp_path / "report.pdf", findings, ENG, _summary(findings), META)
    return path.read_bytes()


def test_pdf_structure_xref_and_titles(tmp_path: Path) -> None:
    findings = [_finding(i) for i in range(1, 13)]
    data = _render(tmp_path, findings)
    assert data.startswith(b"%PDF-1.4")
    assert data.endswith(b"%%EOF")
    pages = data.count(b"/Type /Page ")
    assert pages >= 3, pages
    assert data.count(b"/Type /Pages ") == 1
    assert b"/PageMode" in data
    assert b"/BaseFont /Helvetica-Bold" in data
    for i in range(1, 13):
        assert _esc(_title(i)).encode("latin-1") in data, i
    assert b"caf\xe9 portal" in data       # latin-1 survives to WinAnsi
    assert b'"raw" dumps' in data          # typographic quotes folded to ASCII
    assert b"?? payload" in data           # out-of-WinAnsi dropped to '?'

    start = int(re.search(rb"startxref\s+(\d+)", data).group(1))
    assert data[start:start + 4] == b"xref"
    size = int(re.search(rb"/Size (\d+)", data).group(1))
    block = data[start:].split(b"trailer")[0].splitlines()
    rows = [row for row in block[2:] if row.endswith(b" n ")]
    assert len(rows) == size - 1
    for number, row in enumerate(rows, 1):
        assert data[int(row[:10]):].startswith(f"{number} 0 obj".encode())

    assert int(re.search(rb"\(Page 1 of (\d+)\)", data).group(1)) == pages


def test_pdf_with_no_findings_is_valid(tmp_path: Path) -> None:
    path = pdf.write_pdf(tmp_path / "empty.pdf", [], ENG, _summary([], "Nothing confirmed."), META)
    data = path.read_bytes()
    assert data.startswith(b"%PDF-1.4") and data.endswith(b"%%EOF")
    assert b"No findings were recorded" in data
    assert data.count(b"/Type /Page ") == 1
    start = int(re.search(rb"startxref\s+(\d+)", data).group(1))
    assert data[start:start + 4] == b"xref"


def test_wrap_never_overflows_margins() -> None:
    assert pdf._width("Hello", 10) <= 5 * 10
    lines = pdf._wrap(LONG_URL, 10, pdf.WIDTH)
    assert len(lines) > 1
    assert all(pdf._width(line, 10) <= pdf.WIDTH for line in lines)
    assert "".join(lines) == LONG_URL  # hard break loses nothing
    words = pdf._wrap("word " * 200, 10, pdf.WIDTH)
    assert all(pdf._width(line, 10) <= pdf.WIDTH for line in words)
    assert " ".join(words).split() == ("word " * 200).split()