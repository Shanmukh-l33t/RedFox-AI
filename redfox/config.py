"""RedFox AI — configuration.

Everything tunable lives here or in the engagement record. Nothing about a
target, a model id, or an autonomy ceiling is hardcoded into agent logic.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

AUTONOMY_LEVELS = {
    0: "observe",
    1: "scan",
    2: "validate",
    3: "full-auto",
}

# Risk classes an adapter can declare. Order matters: it is the escalation ladder.
RISK_ORDER = ("passive", "active", "validation", "intrusive")
RISK_RANK = {name: i for i, name in enumerate(RISK_ORDER)}


def _bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    try:
        return int(raw) if raw is not None else default
    except ValueError:
        return default


@dataclass(frozen=True)
class Settings:
    home: Path
    tools_dir: Path
    llm_provider: str
    llm_model: str
    llm_api_key: str
    llm_base_url: str
    llm_max_tokens: int
    llm_timeout_s: int
    rate_per_min: int
    rate_per_target_per_min: int
    max_steps: int
    tool_timeout_s: int
    quiet_hours: str  # "22:00-06:00" or empty
    retention_days: int
    api_token: str = ""  # empty: the API is loopback-only and unauthenticated
    isolate: str = "off"  # "docker" runs each tool in its own image
    docker_network: str = "bridge"

    @property
    def db_path(self) -> Path:
        return self.home / "redfox.db"

    @property
    def audit_path(self) -> Path:
        return self.home / "audit" / "audit.jsonl"

    @property
    def evidence_dir(self) -> Path:
        return self.home / "evidence"

    @property
    def approvals_dir(self) -> Path:
        return self.home / "approvals"

    @property
    def kill_switch_path(self) -> Path:
        return self.home / "KILL"

    @classmethod
    def load(cls, home: str | os.PathLike[str] | None = None) -> "Settings":
        root = Path(
            home or os.environ.get("REDFOX_HOME") or (Path.home() / ".redfox")
        ).expanduser()
        tools = Path(
            os.environ.get("REDFOX_TOOLS_DIR")
            or (Path(__file__).resolve().parent.parent / "tools" / "bin")
        )
        s = cls(
            home=root,
            tools_dir=tools,
            llm_provider=os.environ.get("REDFOX_LLM_PROVIDER", "openai").lower(),
            llm_model=os.environ.get("REDFOX_LLM_MODEL", ""),
            llm_api_key=os.environ.get("REDFOX_LLM_API_KEY", ""),
            llm_base_url=os.environ.get("REDFOX_LLM_BASE_URL", ""),
            llm_max_tokens=_int("REDFOX_LLM_MAX_TOKENS", 2048),
            llm_timeout_s=_int("REDFOX_LLM_TIMEOUT", 300),
            rate_per_min=_int("REDFOX_RATE_PER_MIN", 120),
            rate_per_target_per_min=_int("REDFOX_RATE_PER_TARGET", 60),
            max_steps=_int("REDFOX_MAX_STEPS", 40),
            tool_timeout_s=_int("REDFOX_TOOL_TIMEOUT", 600),
            api_token=os.environ.get("REDFOX_API_TOKEN", ""),
            isolate=os.environ.get("REDFOX_ISOLATE", "off").lower(),
            docker_network=os.environ.get("REDFOX_DOCKER_NETWORK", "bridge"),
            quiet_hours=os.environ.get("REDFOX_QUIET_HOURS", ""),
            retention_days=_int("REDFOX_RETENTION_DAYS", 365),
        )
        for d in (
            s.home,
            s.evidence_dir,
            s.audit_path.parent,
            s.approvals_dir,
        ):
            d.mkdir(parents=True, exist_ok=True)
        return s

    def llm_configured(self) -> bool:
        if self.llm_provider == "ollama":
            return True
        return bool(self.llm_model) and bool(self.llm_api_key)