"""AI providers behind one small interface. The only place that talks to a model API (rule R7).

Each provider receives (system, prompt, thinking) and returns plain text. Prompts are built
only from app/ai/inputs.py, so no client data can reach a provider from here.
"""

from dataclasses import dataclass
from typing import Protocol

import httpx

from app.settings import Settings

TIMEOUT = httpx.Timeout(180.0, connect=15.0)  # "high" thinking can take a while


class AIError(RuntimeError):
    """Shown to the team; never contains the key or the prompt."""


@dataclass(frozen=True)
class AIText:
    text: str
    provider: str
    model: str


class Provider(Protocol):
    name: str
    model: str

    def generate(self, system: str, prompt: str, thinking: str) -> AIText: ...


def _check(resp: httpx.Response, provider: str) -> dict:
    if resp.status_code >= 400:
        # Status and the provider's short error message only; never echo request data.
        try:
            detail = resp.json().get("error", {}).get("message", "")[:200]
        except ValueError:
            detail = ""
        raise AIError(f"{provider} returned HTTP {resp.status_code}. {detail}".strip())
    return resp.json()


class GeminiProvider:
    name = "gemini"

    def __init__(self, api_key: str, model: str, client: httpx.Client | None = None):
        self._key, self.model = api_key, model
        self._client = client or httpx.Client(timeout=TIMEOUT)

    def generate(self, system: str, prompt: str, thinking: str) -> AIText:
        url = (
            f"https://generativelanguage.googleapis.com/v1beta/models/{self.model}:generateContent"
        )
        body = {
            "systemInstruction": {"parts": [{"text": system}]},
            "contents": [{"role": "user", "parts": [{"text": prompt}]}],
            "generationConfig": {"thinkingConfig": {"thinkingLevel": thinking.upper()}},
        }
        data = _check(
            self._client.post(url, json=body, headers={"x-goog-api-key": self._key}), "Gemini"
        )
        try:
            parts = data["candidates"][0]["content"]["parts"]
        except (KeyError, IndexError, TypeError) as e:
            reason = (data.get("promptFeedback") or {}).get("blockReason") or "no text returned"
            raise AIError(f"Gemini returned no answer ({reason}).") from e
        # Skip thought summaries if any are returned; keep the answer text.
        text = "".join(p.get("text", "") for p in parts if not p.get("thought"))
        if not text.strip():
            raise AIError("Gemini returned an empty answer.")
        return AIText(text.strip(), self.name, self.model)


class OpenAIProvider:
    name = "openai"

    def __init__(self, api_key: str, model: str, client: httpx.Client | None = None):
        self._key, self.model = api_key, model
        self._client = client or httpx.Client(timeout=TIMEOUT)

    def generate(self, system: str, prompt: str, thinking: str) -> AIText:
        body = {
            "model": self.model,
            "instructions": system,
            "input": prompt,
            "reasoning": {"effort": thinking.lower()},
        }
        data = _check(
            self._client.post(
                "https://api.openai.com/v1/responses",
                json=body,
                headers={"authorization": f"Bearer {self._key}"},
            ),
            "OpenAI",
        )
        text = "".join(
            c.get("text", "")
            for item in data.get("output", [])
            if item.get("type") == "message"
            for c in item.get("content", [])
            if c.get("type") == "output_text"
        )
        if not text.strip():
            raise AIError("OpenAI returned an empty answer.")
        return AIText(text.strip(), self.name, self.model)


class AnthropicProvider:
    name = "anthropic"

    def __init__(self, api_key: str, model: str, client: httpx.Client | None = None):
        self._key, self.model = api_key, model
        self._client = client or httpx.Client(timeout=TIMEOUT)

    def generate(self, system: str, prompt: str, thinking: str) -> AIText:
        body = {
            "model": self.model,
            "max_tokens": 2000,
            "system": system,
            "messages": [{"role": "user", "content": prompt}],
        }
        data = _check(
            self._client.post(
                "https://api.anthropic.com/v1/messages",
                json=body,
                headers={"x-api-key": self._key, "anthropic-version": "2023-06-01"},
            ),
            "Anthropic",
        )
        text = "".join(
            b.get("text", "") for b in data.get("content", []) if b.get("type") == "text"
        )
        if not text.strip():
            raise AIError("Anthropic returned an empty answer.")
        return AIText(text.strip(), self.name, self.model)


class FakeProvider:
    """Offline and deterministic: for tests and for demos without a key."""

    name = "fake"
    model = "fake-1"

    def generate(self, system: str, prompt: str, thinking: str) -> AIText:
        drill = "PRACTICE" in prompt
        if prompt.startswith("Draft an email"):
            text = ("[DRILL] practice message, do not send to a client\n" if drill else "") + (
                "Subject: Security update for {{SITE_NAME}}\n\n"
                "Hi {{CLIENT_NAME}},\n\n"
                "A security flaw was published that affected software used by {{SITE_NAME}}. "
                "We updated the site on {{FIX_TIME}} and checked that the fix is in place. "
                "There's nothing you need to do.\n\n"
                "Best regards,\n{{SENDER_NAME}}"
            )
        else:
            text = ("PRACTICE drill, not a real vulnerability.\n" if drill else "") + (
                "(Offline summary.) A published flaw affects software on one or more of our "
                "sites. Upgrade to the fixed version shown on each case; a firewall rule only "
                "reduces risk until then. Review each site's file checks for warning signs."
            )
        return AIText(text, self.name, self.model)


def provider_for(settings: Settings) -> Provider:
    name = settings.ai_provider
    if name == "fake":
        return FakeProvider()
    key = {
        "gemini": settings.gemini_api_key,
        "openai": settings.openai_api_key,
        "anthropic": settings.anthropic_api_key,
    }[name]
    model = {
        "gemini": settings.gemini_model,
        "openai": settings.openai_model,
        "anthropic": settings.anthropic_model,
    }[name]
    if key is None or not model:
        raise AIError(f"AI provider '{name}' needs an API key and a model in the settings.")
    cls = {"gemini": GeminiProvider, "openai": OpenAIProvider, "anthropic": AnthropicProvider}
    return cls[name](key.get_secret_value(), model)
