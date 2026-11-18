"""Provider-agnostic LLM access.

Model ids and endpoints are configuration, never code. Supported providers:
  - openai    : any OpenAI-compatible /chat/completions endpoint (default)
  - anthropic : Messages API
  - ollama    : local OpenAI-compatible server (http://127.0.0.1:11434/v1)

All agents ask for JSON. Providers that support JSON mode are told to enforce it
(`response_format: json_object`), which matters most for small local models.
A reply that cannot be parsed is retried once with the parse error attached,
then raised as LLMError so the campaign pauses honestly instead of inventing a
plan.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

import httpx

from .config import Settings


class LLMError(RuntimeError):
    def __init__(self, message: str, raw: str = "") -> None:
        super().__init__(message)
        self.raw = raw


@dataclass
class LLMReply:
    data: dict[str, Any]
    text: str
    model: str
    input_tokens: int = 0
    output_tokens: int = 0


def extract_json(text: str) -> dict[str, Any]:
    """Pull the first JSON object out of a model reply, tolerating fences."""
    cleaned = (text or "").strip()
    if cleaned.startswith("```"):
        cleaned = cleaned.split("```", 2)[1] if cleaned.count("```") >= 2 else cleaned[3:]
        if cleaned.lstrip().lower().startswith("json"):
            cleaned = cleaned.lstrip()[4:]
    start = cleaned.find("{")
    if start < 0:
        raise ValueError("no JSON object in reply")
    try:
        obj, _ = json.JSONDecoder().raw_decode(cleaned[start:])
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid JSON: {exc}") from exc
    if not isinstance(obj, dict):
        raise ValueError("reply must be a JSON object")
    return obj


class LLMClient:
    def __init__(self, settings: Settings,
                 transport: httpx.AsyncBaseTransport | None = None) -> None:
        self.settings = settings
        self.provider = settings.llm_provider
        self.model = settings.llm_model
        self.api_key = settings.llm_api_key
        self.base_url = settings.llm_base_url or self._default_base()
        self.transport = transport

    def _default_base(self) -> str:
        return {
            "anthropic": "https://api.anthropic.com",
            "ollama": "http://127.0.0.1:11434/v1",
            "openai": "https://api.openai.com/v1",
        }.get(self.provider, "https://api.openai.com/v1")

    @property
    def configured(self) -> bool:
        if self.provider == "ollama":
            return True
        return bool(self.model and self.api_key)

    async def complete(self, system: str, user: str,
                       max_tokens: int | None = None) -> LLMReply:
        if not self.configured:
            raise LLMError(
                "no LLM configured: set REDFOX_LLM_PROVIDER / REDFOX_LLM_MODEL / "
                "REDFOX_LLM_API_KEY (or run a local Ollama server)"
            )
        budget = max_tokens or self.settings.llm_max_tokens
        if self.provider == "anthropic":
            return await self._anthropic(system, user, budget)
        return await self._openai_compatible(system, user, budget)

    async def json_reply(self, system: str, user: str, retries: int = 1,
                         max_tokens: int | None = None) -> LLMReply:
        last_error = ""
        for attempt in range(retries + 1):
            prompt = user if attempt == 0 else (
                f"{user}\n\nYour previous reply could not be parsed as JSON ({last_error}). "
                "Reply with one JSON object and nothing else."
            )
            reply = await self.complete(system, prompt, max_tokens)
            try:
                reply.data = extract_json(reply.text)
                return reply
            except ValueError as exc:
                last_error = str(exc)
                if attempt == retries:
                    raise LLMError(f"model did not return JSON: {last_error}",
                                   raw=reply.text) from exc
        raise LLMError("unreachable")

    async def _openai_compatible(self, system: str, user: str, budget: int) -> LLMReply:
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "temperature": 0.2,
            "max_tokens": budget,
            "response_format": {"type": "json_object"},
        }
        headers = {"Authorization": f"Bearer {self.api_key or 'local'}"}
        url = self.base_url.rstrip("/") + "/chat/completions"
        try:
            async with httpx.AsyncClient(timeout=float(self.settings.llm_timeout_s), transport=self.transport) as client:
                resp = await client.post(url, json=payload, headers=headers)
                resp.raise_for_status()
                body = resp.json()
        except Exception as exc:
            raise LLMError(f"{type(exc).__name__}: {exc}") from exc
        choices = body.get("choices") or []
        if not choices:
            raise LLMError("provider returned no choices")
        text = (choices[0].get("message") or {}).get("content") or ""
        usage = body.get("usage") or {}
        return LLMReply(
            data={}, text=text, model=body.get("model", self.model),
            input_tokens=int(usage.get("prompt_tokens") or 0),
            output_tokens=int(usage.get("completion_tokens") or 0),
        )

    async def _anthropic(self, system: str, user: str, budget: int) -> LLMReply:
        payload = {
            "model": self.model,
            "system": system,
            "max_tokens": budget,
            "temperature": 0.2,
            "messages": [{"role": "user", "content": user}],
        }
        headers = {
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        }
        url = self.base_url.rstrip("/") + "/v1/messages"
        try:
            async with httpx.AsyncClient(timeout=float(self.settings.llm_timeout_s), transport=self.transport) as client:
                resp = await client.post(url, json=payload, headers=headers)
                resp.raise_for_status()
                body = resp.json()
        except Exception as exc:
            raise LLMError(f"{type(exc).__name__}: {exc}") from exc
        text = "".join(
            block.get("text", "") for block in body.get("content", [])
            if isinstance(block, dict)
        )
        usage = body.get("usage") or {}
        return LLMReply(
            data={}, text=text, model=body.get("model", self.model),
            input_tokens=int(usage.get("input_tokens") or 0),
            output_tokens=int(usage.get("output_tokens") or 0),
        )