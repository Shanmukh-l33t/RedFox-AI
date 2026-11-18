"""Structural guarantees: properties that must hold by construction, not convention.

If any of these fail, the safety story in the README is false.
"""

from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PKG = ROOT / "redfox"


def test_only_runtime_may_spawn_processes() -> None:
    offenders = []
    for path in PKG.rglob("*.py"):
        if path.name == "runtime.py":
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names = {a.name for a in node.names}
                if names & {"subprocess", "multiprocessing"}:
                    offenders.append(str(path.relative_to(ROOT)))
            elif isinstance(node, ast.ImportFrom) and node.module in {
                "subprocess", "multiprocessing"
            }:
                offenders.append(str(path.relative_to(ROOT)))
            elif isinstance(node, ast.Call):
                func = node.func
                if isinstance(func, ast.Attribute) and func.attr in {
                    "system", "popen", "spawnl", "spawnv", "execv", "execvp", "fork",
                }:
                    offenders.append(str(path.relative_to(ROOT)))
    assert not offenders, f"process creation outside runtime.py: {sorted(set(offenders))}"


def test_adapters_do_not_import_runtime_or_db() -> None:
    adapter_dir = PKG / "adapters"
    if not adapter_dir.exists():
        return
    for path in adapter_dir.rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        assert "import subprocess" not in text, path
        assert "from ..runtime import" not in text, f"{path} reaches into the runtime"


def test_no_shell_true_anywhere() -> None:
    needle = "shell" + "=True"
    this_file = Path(__file__).resolve()
    for path in ROOT.rglob("*.py"):
        if ".venv" in path.parts or path.resolve() == this_file:
            continue
        assert needle not in path.read_text(encoding="utf-8", errors="ignore"), path