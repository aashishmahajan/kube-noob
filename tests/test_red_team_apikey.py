"""Red team RT2: the optional model path, exercised with a key set.

A key in the environment turns on the only two commands that call a model (``ask`` and ``train bench``, plus the
eval judge). These tests cover what goes wrong around that key rather than what the model answers: which variable
is read for which provider, whether the key can reach a host the user did not configure, whether it can be echoed
back out of an error body, and whether an unexpected response shape ends in a message or a traceback.
"""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest

from kube_noob.agent.providers import DEFAULT_KEY_ENV, build_provider, key_env
from kube_noob.config import load_settings
from kube_noob.errors import ConfigError, ProviderError

ANTHROPIC_KEY = "sk-ant-not-a-real-key-0123456789"


def _stub(monkeypatch: pytest.MonkeyPatch, handler: Any) -> list[httpx.Request]:
    """Answer every outbound request from ``handler`` and record what was sent."""
    seen: list[httpx.Request] = []

    def _handle(self: Any, request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return handler(request)

    monkeypatch.setattr(httpx.HTTPTransport, "handle_request", _handle)
    return seen


def _openai(**llm: Any) -> Any:
    s = load_settings(overrides={"llm": {"provider": "openai-compatible", **llm}})
    return build_provider(s.llm, s)


def test_the_anthropic_key_is_never_the_default_for_another_endpoint(monkeypatch: pytest.MonkeyPatch) -> None:
    """RT2-1. ``openai-compatible`` with no ``apiKeyEnv`` must not reach for ANTHROPIC_API_KEY: the endpoint is any
    third-party gateway the user named, and the Anthropic key is not its credential to receive."""
    monkeypatch.setenv(DEFAULT_KEY_ENV, ANTHROPIC_KEY)
    s = load_settings(overrides={"llm": {"provider": "openai-compatible", "baseUrl": "https://third.example/v1"}})
    assert key_env(s.llm) is None
    seen = _stub(monkeypatch, lambda r: httpx.Response(200, json={"choices": [{"message": {"content": "hi"}}]}))
    _openai(baseUrl="https://third.example/v1").complete_text("q")
    assert seen and "authorization" not in {k.lower() for k in seen[0].headers}
    assert ANTHROPIC_KEY not in seen[0].headers.get("authorization", "")

    # Named explicitly, the same variable is sent - the user asked for that.
    _stub(monkeypatch, lambda r: httpx.Response(200, json={"choices": [{"message": {"content": "hi"}}]}))
    p = _openai(baseUrl="https://third.example/v1", apiKeyEnv=DEFAULT_KEY_ENV)
    assert p.key == ANTHROPIC_KEY


def test_anthropic_still_defaults_to_its_own_variable(monkeypatch: pytest.MonkeyPatch) -> None:
    """RT2-1b. Narrowing the default must not break the documented ``ANTHROPIC_API_KEY`` path."""
    monkeypatch.delenv(DEFAULT_KEY_ENV, raising=False)
    s = load_settings(overrides={"llm": {"provider": "anthropic"}})
    assert key_env(s.llm) == DEFAULT_KEY_ENV
    with pytest.raises(ProviderError, match=DEFAULT_KEY_ENV):
        build_provider(s.llm, s)


def test_a_missing_key_for_a_remote_endpoint_names_the_setting(monkeypatch: pytest.MonkeyPatch) -> None:
    """RT2-5. A remote endpoint refusing an unauthenticated request should point at ``llm.apiKeyEnv`` rather than
    leaving the user to guess why a 401 came back."""
    monkeypatch.delenv(DEFAULT_KEY_ENV, raising=False)
    _stub(monkeypatch, lambda r: httpx.Response(401, text="unauthorized"))
    with pytest.raises(ProviderError, match="apiKeyEnv"):
        _openai(baseUrl="https://third.example/v1").complete_text("q")


def test_an_echoed_key_is_redacted_from_the_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """RT2-2. A gateway that quotes the Authorization header back in its error body must not have that body
    printed verbatim: the error reaches stderr, logs and CI output."""
    monkeypatch.setenv("GATEWAY_API_KEY", ANTHROPIC_KEY)
    _stub(monkeypatch, lambda r: httpx.Response(400, text=f"bad header: Bearer {ANTHROPIC_KEY}"))
    with pytest.raises(ProviderError) as exc:
        _openai(baseUrl="https://third.example/v1", apiKeyEnv="GATEWAY_API_KEY").complete_text("q")
    assert ANTHROPIC_KEY not in str(exc.value)
    assert "[redacted]" in str(exc.value)

    _stub(monkeypatch, lambda r: httpx.Response(200, text=f"Bearer {ANTHROPIC_KEY}"))
    with pytest.raises(ProviderError) as nonjson:
        _openai(baseUrl="https://third.example/v1", apiKeyEnv="GATEWAY_API_KEY").complete_text("q")
    assert ANTHROPIC_KEY not in str(nonjson.value)


@pytest.mark.parametrize(
    "body",
    [
        {"choices": []},
        {"choices": [{"message": "a string, not an object"}]},
        {"choices": "not a list"},
        {},
        [],
    ],
)
def test_an_unexpected_response_shape_is_an_error_not_a_traceback(monkeypatch: pytest.MonkeyPatch, body: Any) -> None:
    """RT2-3. Any 200 that is not the documented shape ends in a ProviderError. A model endpoint is not trusted
    input: a proxy, a captive portal or a different API version can all answer 200 with something else."""
    monkeypatch.setenv("GATEWAY_API_KEY", "k")
    _stub(monkeypatch, lambda r: httpx.Response(200, json=body))
    p = _openai(baseUrl="https://third.example/v1", apiKeyEnv="GATEWAY_API_KEY")
    with pytest.raises(ProviderError):
        p.complete_text("q")
    _stub(monkeypatch, lambda r: httpx.Response(200, json=body))
    with pytest.raises(ProviderError):
        p.turn("sys", [{"role": "user", "content": "q"}], [])


def test_a_redirect_loop_is_an_error_not_a_traceback(monkeypatch: pytest.MonkeyPatch) -> None:
    """RT2-3b. httpx raises TooManyRedirects rather than returning a response; uncaught it is a traceback, and each
    hop carried the key."""
    monkeypatch.setenv("GATEWAY_API_KEY", "k")
    _stub(monkeypatch, lambda r: httpx.Response(307, headers={"location": "https://third.example/v1/again"}))
    with pytest.raises(ProviderError, match="redirect"):
        _openai(baseUrl="https://third.example/v1", apiKeyEnv="GATEWAY_API_KEY").complete_text("q")


def test_the_cleartext_guard_covers_the_endpoint_from_the_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    """RT2-4. ``llm.baseUrl: http://remote`` is refused because the key would travel in clear text. The SDK reads
    ANTHROPIC_BASE_URL on its own, so the same URL must be refused when it arrives that way."""
    monkeypatch.setenv(DEFAULT_KEY_ENV, ANTHROPIC_KEY)
    monkeypatch.setenv("ANTHROPIC_BASE_URL", "http://gateway.example/v1")
    s = load_settings(overrides={"llm": {"provider": "anthropic"}})
    with pytest.raises(ProviderError, match="clear text"):
        build_provider(s.llm, s)
    monkeypatch.setenv("ANTHROPIC_BASE_URL", "http://127.0.0.1:8080")
    assert build_provider(s.llm, s).name == "anthropic"
    monkeypatch.setenv("ANTHROPIC_BASE_URL", "https://gateway.example/v1")
    assert build_provider(s.llm, s).name == "anthropic"


def test_apikeyenv_may_not_name_a_non_key_variable() -> None:
    """RT2-6. ``apiKeyEnv`` reaches straight into the environment and the value is sent as a bearer token, so it may
    only name a model provider's key - not the MCP server's own token, which the same process holds."""
    for name in ("KUBE_NOOB_HTTP_TOKEN", "KUBE_NOOB_SECRET", "GITHUB_TOKEN", "AWS_SECRET_ACCESS_KEY", "HOME"):
        with pytest.raises(ConfigError):
            load_settings(overrides={"llm": {"apiKeyEnv": name}})
    for ok in ("VLLM_API_KEY", "ANTHROPIC_API_KEY", "KUBE_NOOB_LLM_API_KEY"):
        assert load_settings(overrides={"llm": {"apiKeyEnv": ok}}).llm.api_key_env == ok


def test_the_offline_lock_still_wins_with_a_key_set(monkeypatch: pytest.MonkeyPatch) -> None:
    """RT2 regression: none of the above may open a path out under the lock."""
    monkeypatch.setenv("KUBE_NOOB_OFFLINE", "1")
    monkeypatch.setenv(DEFAULT_KEY_ENV, ANTHROPIC_KEY)
    monkeypatch.setenv("ANTHROPIC_BASE_URL", "https://gateway.example/v1")
    seen = _stub(monkeypatch, lambda r: httpx.Response(200, json={}))
    for over in (
        {"provider": "anthropic"},
        {"provider": "openai-compatible", "baseUrl": "https://third.example/v1", "apiKeyEnv": "VLLM_API_KEY"},
    ):
        s = load_settings(overrides={"llm": over})
        with pytest.raises(ProviderError, match="offline"):
            build_provider(s.llm, s)
    assert seen == []


def test_the_key_is_not_in_the_json_answer(monkeypatch: pytest.MonkeyPatch) -> None:
    """RT2 leak check: --format json is pasted into tickets, so nothing in it may carry the key."""
    monkeypatch.setenv("GATEWAY_API_KEY", ANTHROPIC_KEY)
    _stub(monkeypatch, lambda r: httpx.Response(200, json={"choices": [{"message": {"content": "answer"}}]}))
    turn = _openai(baseUrl="https://third.example/v1", apiKeyEnv="GATEWAY_API_KEY").turn(
        "sys", [{"role": "user", "content": "q"}], []
    )
    assert ANTHROPIC_KEY not in json.dumps({"text": turn.text, "raw": turn.raw_assistant, "notes": turn.notes})


def test_a_null_content_is_an_empty_answer_not_an_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """The counterpart to RT2-3: ``content: null`` is what a tool-call-only turn looks like, so it stays a valid
    response. Hardening the shape check must not start refusing the endpoint's own documented reply."""
    monkeypatch.setenv("GATEWAY_API_KEY", "k")
    _stub(monkeypatch, lambda r: httpx.Response(200, json={"choices": [{"message": {"content": None}}]}))
    assert _openai(baseUrl="https://third.example/v1", apiKeyEnv="GATEWAY_API_KEY").complete_text("q") == ""
