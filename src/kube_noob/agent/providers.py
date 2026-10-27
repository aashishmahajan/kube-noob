"""LLM providers for the standalone agent.

* ``anthropic``          - Claude via the Anthropic API (default model ``claude-fable-5-1``). Supports server-side
                           fallbacks when the requested model's safety classifier declines (security tooling can trip
                           cyber classifiers) and Anthropic's server-side web search when ``webEnabled`` is true.
* ``openai-compatible``  - any ``/v1/chat/completions`` endpoint with tool calling (vLLM, Ollama, LM Studio, TGI) -
                           this is how a model you fine-tune later plugs in.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Any, Protocol

import httpx

from kube_noob.config import LLMSettings, Settings
from kube_noob.errors import ProviderError
from kube_noob.net import Purpose, http_client

FALLBACK_BETA = "server-side-fallback-2026-07-01"


@dataclass
class ToolCall:
    call_id: str
    name: str
    arguments: dict[str, Any]


@dataclass
class Turn:
    text: str
    tool_calls: list[ToolCall]
    stop_reason: str
    model: str
    raw_assistant: Any  # provider-native assistant message to append to history
    notes: list[str] = field(default_factory=list)


class Provider(Protocol):
    name: str
    model: str

    def turn(self, system: str, messages: list[dict[str, Any]], tools: list[dict[str, Any]]) -> Turn: ...

    def tool_results_message(self, results: list[tuple[ToolCall, str, bool]]) -> list[dict[str, Any]]: ...

    def user_message(self, text: str) -> dict[str, Any]: ...

    def complete_text(self, prompt: str, max_tokens: int = 1024) -> str: ...


def _api_key(llm: LLMSettings) -> str:
    key = os.environ.get(llm.api_key_env, "")
    if not key:
        raise ProviderError(
            f"Environment variable {llm.api_key_env} is not set; the agent needs an API key for "
            f"provider '{llm.provider}'."
        )
    return key


class AnthropicProvider:
    name = "anthropic"

    def __init__(self, llm: LLMSettings, settings: Settings, fallbacks: bool = True) -> None:
        import anthropic

        self.model = llm.model
        self.llm = llm
        self.settings = settings
        self.fallbacks = fallbacks
        kwargs: dict[str, Any] = {"api_key": _api_key(llm), "timeout": llm.timeout_seconds, "max_retries": 3}
        if llm.base_url:
            kwargs["base_url"] = llm.base_url
        self.client = anthropic.Anthropic(**kwargs)

    def _server_tools(self) -> list[dict[str, Any]]:
        if not self.settings.web_enabled:
            return []
        return [
            {
                "type": "web_search_20250305",
                "name": "web_search",
                "max_uses": 5,
                "allowed_domains": list(self.settings.web.allowed_domains),
            }
        ]

    def _create(self, **kw: Any) -> Any:
        import anthropic

        try:
            if self.fallbacks:
                try:
                    return self.client.beta.messages.create(fallbacks="default", betas=[FALLBACK_BETA], **kw)
                except anthropic.APIStatusError as exc:
                    if "fallback" not in str(exc).lower() and "beta" not in str(exc).lower():
                        raise
                    self.fallbacks = False
            return self.client.messages.create(**kw)
        except anthropic.APIConnectionError as exc:
            raise ProviderError(f"Cannot reach the Anthropic API ({exc}). Check network/proxy access.") from exc
        except anthropic.AuthenticationError as exc:
            raise ProviderError("The Anthropic API rejected the key in llm.apiKeyEnv (HTTP 401).") from exc
        except anthropic.APIStatusError as exc:
            raise ProviderError(f"Anthropic API error HTTP {exc.status_code}: {str(exc)[:300]}") from exc

    def turn(self, system: str, messages: list[dict[str, Any]], tools: list[dict[str, Any]]) -> Turn:
        anth_tools = [
            {"name": t["name"], "description": t["description"], "input_schema": t["input_schema"]} for t in tools
        ] + self._server_tools()
        resp = self._create(
            model=self.model, max_tokens=self.llm.max_tokens, system=system, messages=messages, tools=anth_tools
        )
        text_parts: list[str] = []
        calls: list[ToolCall] = []
        notes: list[str] = []
        for block in resp.content:
            btype = getattr(block, "type", "")
            if btype == "text":
                text_parts.append(block.text)
            elif btype == "tool_use":
                calls.append(ToolCall(block.id, block.name, dict(block.input or {})))
            elif btype == "fallback":
                notes.append(
                    f"served by fallback model {block.to.model} (requested {block.from_.model})"
                    if hasattr(block, "from_")
                    else "served by a fallback model"
                )
        if resp.stop_reason == "refusal":
            details = getattr(resp, "stop_details", None)
            notes.append(f"model declined: {getattr(details, 'explanation', '') or 'refusal'}")
        # Keep thinking/tool_use/server-tool blocks verbatim (required for multi-turn tool use); the fallback marker is
        # response metadata, not conversation content.
        raw = {
            "role": "assistant",
            "content": [b.model_dump(exclude_none=True) for b in resp.content if getattr(b, "type", "") != "fallback"],
        }
        return Turn("".join(text_parts), calls, str(resp.stop_reason), str(resp.model), raw, notes)

    def tool_results_message(self, results: list[tuple[ToolCall, str, bool]]) -> list[dict[str, Any]]:
        return [
            {
                "role": "user",
                "content": [
                    {"type": "tool_result", "tool_use_id": c.call_id, "content": out, "is_error": err}
                    for c, out, err in results
                ],
            }
        ]

    def user_message(self, text: str) -> dict[str, Any]:
        return {"role": "user", "content": text}

    def complete_text(self, prompt: str, max_tokens: int = 1024) -> str:
        resp = self._create(model=self.model, max_tokens=max_tokens, messages=[{"role": "user", "content": prompt}])
        return "".join(b.text for b in resp.content if getattr(b, "type", "") == "text")


class OpenAICompatibleProvider:
    name = "openai-compatible"

    def __init__(self, llm: LLMSettings, settings: Settings) -> None:
        if not llm.base_url:
            raise ProviderError(
                "llm.baseUrl is required for provider 'openai-compatible' (e.g. "
                "http://localhost:8000/v1 for vLLM, http://localhost:11434/v1 for Ollama)."
            )
        self.model = llm.model
        self.llm = llm
        self.settings = settings
        self.base = llm.base_url.rstrip("/")
        self.key = os.environ.get(llm.api_key_env, "")

    def _post(self, payload: dict[str, Any]) -> dict[str, Any]:
        headers = {"Content-Type": "application/json"}
        if self.key:
            headers["Authorization"] = f"Bearer {self.key}"
        try:
            with http_client(self.settings, Purpose.LLM, timeout=self.llm.timeout_seconds, extra_headers=headers) as c:
                resp = c.post(f"{self.base}/chat/completions", content=json.dumps(payload))
        except httpx.TimeoutException as exc:
            raise ProviderError(
                f"{self.base} did not answer within {self.llm.timeout_seconds}s (llm.timeoutSeconds)"
            ) from exc
        except httpx.TransportError as exc:
            raise ProviderError(f"Cannot reach the model endpoint {self.base}: {exc}") from exc
        if resp.status_code >= 400:
            raise ProviderError(f"{self.base} returned HTTP {resp.status_code}: {resp.text[:300]}")
        try:
            return resp.json()  # type: ignore[no-any-return]
        except ValueError as exc:
            raise ProviderError(f"{self.base} returned a non-JSON response: {resp.text[:200]}") from exc

    def turn(self, system: str, messages: list[dict[str, Any]], tools: list[dict[str, Any]]) -> Turn:
        payload = {
            "model": self.model,
            "max_tokens": self.llm.max_tokens,
            "messages": [{"role": "system", "content": system}, *messages],
            "tools": [
                {
                    "type": "function",
                    "function": {"name": t["name"], "description": t["description"], "parameters": t["input_schema"]},
                }
                for t in tools
            ],
        }
        data = self._post(payload)
        choice = (data.get("choices") or [{}])[0]
        msg = choice.get("message") or {}
        calls = []
        for tc in msg.get("tool_calls") or []:
            fn = tc.get("function") or {}
            try:
                args = json.loads(fn.get("arguments") or "{}")
            except json.JSONDecodeError:
                args = {"__invalid_json__": fn.get("arguments")}
            calls.append(ToolCall(str(tc.get("id")), str(fn.get("name")), args if isinstance(args, dict) else {}))
        raw = {
            "role": "assistant",
            "content": msg.get("content") or "",
            **({"tool_calls": msg["tool_calls"]} if msg.get("tool_calls") else {}),
        }
        return Turn(
            msg.get("content") or "", calls, str(choice.get("finish_reason")), str(data.get("model", self.model)), raw
        )

    def tool_results_message(self, results: list[tuple[ToolCall, str, bool]]) -> list[dict[str, Any]]:
        return [{"role": "tool", "tool_call_id": c.call_id, "content": out} for c, out, _ in results]

    def user_message(self, text: str) -> dict[str, Any]:
        return {"role": "user", "content": text}

    def complete_text(self, prompt: str, max_tokens: int = 1024) -> str:
        data = self._post(
            {"model": self.model, "max_tokens": max_tokens, "messages": [{"role": "user", "content": prompt}]}
        )
        return str(((data.get("choices") or [{}])[0].get("message") or {}).get("content") or "")


def build_provider(llm: LLMSettings, settings: Settings) -> Provider:
    if llm.provider == "anthropic":
        return AnthropicProvider(llm, settings)
    if llm.provider == "openai-compatible":
        return OpenAICompatibleProvider(llm, settings)
    raise ProviderError("llm.provider is 'none'; configure 'anthropic' or 'openai-compatible' to use the agent.")
