"""Append-only, tamper-evident audit log.

Each record carries the hash of the previous record. Editing or deleting a line
breaks verification from that point on, which is what makes the trail usable as
an engagement record.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

GENESIS = "0" * 64


def _canonical(payload: dict[str, Any]) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


class AuditLog:
    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        if not self.path.exists():
            self.path.write_text("", encoding="utf-8")

    def _last_hash(self) -> str:
        last = GENESIS
        with self.path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    last = json.loads(line).get("hash", last)
        return last

    def append(self, record: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            entry = dict(record)
            entry.setdefault("ts", datetime.now(timezone.utc).isoformat(timespec="milliseconds"))
            entry["prev"] = self._last_hash()
            entry["hash"] = hashlib.sha256(
                (entry["prev"] + _canonical({k: v for k, v in entry.items() if k != "hash"}))
                .encode("utf-8")
            ).hexdigest()
            with self.path.open("a", encoding="utf-8", newline="\n") as fh:
                fh.write(_canonical(entry) + "\n")
                fh.flush()
                os.fsync(fh.fileno())
            return entry

    def verify(self) -> tuple[bool, str]:
        prev = GENESIS
        count = 0
        with self.path.open("r", encoding="utf-8") as fh:
            for lineno, line in enumerate(fh, 1):
                line = line.strip()
                if not line:
                    continue
                entry = json.loads(line)
                if entry.get("prev") != prev:
                    return False, f"chain break at line {lineno}: prev hash mismatch"
                body = {k: v for k, v in entry.items() if k != "hash"}
                expected = hashlib.sha256((prev + _canonical(body)).encode("utf-8")).hexdigest()
                if entry.get("hash") != expected:
                    return False, f"hash mismatch at line {lineno}"
                prev = entry["hash"]
                count += 1
        return True, f"{count} records verified"

    def records(self, engagement_id: str | None = None) -> list[dict[str, Any]]:
        out = []
        with self.path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                entry = json.loads(line)
                if engagement_id is None or entry.get("engagement_id") == engagement_id:
                    out.append(entry)
        return out