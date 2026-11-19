"""LLM client behaviour that has bitten real providers."""

from __future__ import annotations

import json

import httpx
import pytest

from redfox.config import Settings
from redfox.llm import LLMClient, LLMError, extract_json


def client(tmp_path, handler, provider="openai") -> LLMClient:
    settings = Settings.load(home=tmp_path / "llm")
    settings = type(settings)(**{**settings.__dict__,
                                 "llm_provider": provider,
                                 "llm_model": "test-model",
                                 "llm_api_key": "test",
                                 "llm_base_url": "https://example.test/v1"})
    return LLMClient(settings, transport=httpx.MockTransport(handler))


def test_empty_reply_is_retried_with_more_room_and_no_json_mode(tmp_path) -> None:
    seen = []

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        seen.append(body)
        if len(seen) == 1:
            return httpx.Response(200, json={"choices": [{"message": {"content": ""}}]})
        return httpx.Response(200, json={"choices": [{"message": {"content": '{"ok": true}'}}],
                                         "usage": {"prompt_tokens": 5, "completion_tokens": 3}})

    reply = __import__("asyncio").run(
        client(tmp_path, handler).complete("sys", "user", max_tokens=200))
    assert reply.text == '{"ok": true}'
    assert len(seen) == 2
    assert seen[0]["max_tokens"] == 200 and "response_format" in seen[0]
    assert seen[1]["max_tokens"] == 800 and "response_format" not in seen[1]
    assert reply.input_tokens == 5 and reply.output_tokens == 3


def test_no_choices_raises(tmp_path) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"choices": []})

    with pytest.raises(LLMError):
        __import__("asyncio").run(client(tmp_path, handler).complete("s", "u"))


def test_http_error_raises_llm_error(tmp_path) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"error": "bad key"})

    with pytest.raises(LLMError):
        __import__("asyncio").run(client(tmp_path, handler).complete("s", "u"))


def test_truncated_reply_is_retried_with_more_room(tmp_path) -> None:
    seen = []

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        seen.append(body)
        if len(seen) == 1:
            return httpx.Response(200, json={"choices": [{
                "message": {"content": '{"findings": [{"title": "cut off mid'},
                "finish_reason": "length"}]})
        return httpx.Response(200, json={"choices": [{
            "message": {"content": '{"findings": []}'}, "finish_reason": "stop"}]})

    reply = __import__("asyncio").run(
        client(tmp_path, handler).json_reply("sys", "user", max_tokens=100))
    assert reply.data == {"findings": []}
    assert seen[1]["max_tokens"] == 400


def test_json_reply_repairs_once(tmp_path) -> None:
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        content = "I think probative text without json" if calls["n"] == 1 else '{"tasks": []}'
        return httpx.Response(200, json={"choices": [{"message": {"content": content}}]})

    reply = __import__("asyncio").run(
        client(tmp_path, handler).json_reply("sys", "user", retries=1))
    assert reply.data == {"tasks": []}
    assert calls["n"] == 2


def test_extract_json_handles_fences_and_prose() -> None:
    assert extract_json('```json\n{"a": 1}\n```') == {"a": 1}
    assert extract_json('Sure. {"a": 2} Hope that helps.') == {"a": 2}
    with pytest.raises(ValueError):
        extract_json("no json at all")