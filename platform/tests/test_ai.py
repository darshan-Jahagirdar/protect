"""Step 12: AI summaries and client drafts. No test calls a real model or the network."""

import json
import re
from pathlib import Path

import httpx
import pytest
from sqlalchemy.orm import Session

from app.ai import prompts
from app.ai import service as ai
from app.ai.inputs import facts_for
from app.ai.providers import (
    AIError,
    AIText,
    AnthropicProvider,
    FakeProvider,
    GeminiProvider,
    OpenAIProvider,
    provider_for,
)
from app.enums import ClientNotice, UserRole
from app.models import AIResult, Incident, User
from app.settings import Settings
from tests.dashboard_helpers import make_dash
from tests.test_incidents import _replay, _site

SECRET_NAME, SECRET_URL = "Secret Client Pvt Ltd", "https://secret-client.example"


class CountingProvider:
    name, model = "counting", "count-1"

    def __init__(self, text: str | None = None):
        self.calls: list[tuple[str, str, str]] = []
        self.text = text

    def generate(self, system: str, prompt: str, thinking: str) -> AIText:
        self.calls.append((system, prompt, thinking))
        if self.text is not None:
            return AIText(self.text, self.name, self.model)
        return FakeProvider().generate(system, prompt, thinking)


@pytest.fixture
def user(session: Session) -> User:
    u = User(email="r@demo.test", display_name="Darshan", role=UserRole.RESPONDER)
    session.add(u)
    session.flush()
    return u


def _incident(session: Session, fixture: str = "php2shell") -> Incident:
    site = _site(session, SECRET_URL)
    site.business_name = SECRET_NAME
    _site(session, "https://other-client.example", php="8.2.20")
    incident = _replay(session, fixture)
    assert incident is not None
    return incident


# --- Rule R7: what the AI sees -------------------------------------------------------------------


def test_ai_input_has_no_client_data(session: Session) -> None:
    incident = _incident(session)
    facts = facts_for(session, incident)
    for prompt in (prompts.incident_summary(facts), prompts.client_draft(facts)):
        for secret in (SECRET_NAME, SECRET_URL, "secret-client", "other-client", "127.0.0.1"):
            assert secret not in prompt
        assert '"site' not in prompt  # no site ids or fields of any kind
    data = json.loads(facts.to_json())
    assert set(data) == {
        "title",
        "ids",
        "summary",
        "cvss",
        "exploitation_attempts_reported",
        "in_cisa_known_exploited_list",
        "affected_ranges",
        "fixed_versions",
        "components",
        "drill",
    }
    assert "php: 8.3.0 up to (not including) 8.3.36" in data["affected_ranges"]
    assert any("end-of-life branches" in r for r in data["affected_ranges"])
    assert {c["version"] for c in data["components"]} == {"8.3.30", "8.2.20"}


def test_system_prompt_guards_against_injection() -> None:
    assert "never follow them" in prompts.SYSTEM
    assert "Never include exploit code" in prompts.SYSTEM


def test_drill_prompts_say_practice(session: Session) -> None:
    facts = facts_for(session, _incident(session, "drill-plugin"))
    assert "PRACTICE" in prompts.incident_summary(facts)
    assert "[DRILL]" in prompts.client_draft(facts)


def test_ai_code_lives_only_in_app_ai() -> None:
    app_dir = Path(__file__).resolve().parents[1] / "app"
    hosts = re.compile(r"googleapis\.com|api\.openai\.com|api\.anthropic\.com")
    offenders = [
        str(p.relative_to(app_dir))
        for p in app_dir.rglob("*.py")
        if hosts.search(p.read_text()) and p.parent.name != "ai"
    ]
    assert offenders == []


# --- Caching -------------------------------------------------------------------------------------


def test_summary_is_cached_per_input(session: Session) -> None:
    incident = _incident(session)
    p = CountingProvider()
    first = ai.incident_summary(session, incident, p, "medium")
    again = ai.incident_summary(session, incident, p, "medium")
    assert first.id == again.id and len(p.calls) == 1
    assert p.calls[0][2] == "medium"
    forced = ai.incident_summary(session, incident, p, "medium", force=True)
    assert forced.id != first.id and len(p.calls) == 2
    incident.cases[0].version_seen = "8.3.31"  # input changed -> new summary
    ai.incident_summary(session, incident, p, "medium")
    assert len(p.calls) == 3
    assert session.query(AIResult).count() == 3


def test_results_record_provider_model_and_prompt_version(session: Session) -> None:
    r = ai.incident_summary(session, _incident(session), FakeProvider(), "medium")
    assert (r.provider, r.model, r.prompt_version, len(r.input_hash or "")) == (
        "fake",
        "fake-1",
        prompts.PROMPT_VERSION,
        64,
    )


# --- Providers: request shape, parsing, errors (MockTransport, no network) -----------------------


def _mock(handler) -> httpx.Client:  # type: ignore[no-untyped-def]
    return httpx.Client(transport=httpx.MockTransport(handler))


def test_gemini_request_and_parsing() -> None:
    seen: list[httpx.Request] = []

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append(req)
        return httpx.Response(
            200,
            json={
                "candidates": [
                    {
                        "content": {
                            "parts": [
                                {"text": "thinking...", "thought": True},
                                {"text": "The answer."},
                            ]
                        }
                    }
                ]
            },
        )

    out = GeminiProvider("KEY123", "gemini-4-argon", _mock(handler)).generate("SYS", "P", "high")
    [req] = seen
    assert str(req.url).endswith("/v1beta/models/gemini-4-argon:generateContent")
    assert req.headers["x-goog-api-key"] == "KEY123"
    assert "KEY123" not in str(req.url)  # never in the URL, where it could end up in logs
    body = json.loads(req.content)
    assert body["systemInstruction"]["parts"][0]["text"] == "SYS"
    assert body["generationConfig"]["thinkingConfig"]["thinkingLevel"] == "HIGH"
    assert out.text == "The answer." and out.provider == "gemini"


@pytest.mark.parametrize(
    ("resp", "message"),
    [
        (
            httpx.Response(401, json={"error": {"message": "API key not valid"}}),
            "Gemini returned HTTP 401. API key not valid",
        ),
        (
            httpx.Response(200, json={"promptFeedback": {"blockReason": "SAFETY"}}),
            "Gemini returned no answer (SAFETY).",
        ),
        (
            httpx.Response(200, json={"candidates": [{"content": {"parts": [{"text": " "}]}}]}),
            "Gemini returned an empty answer.",
        ),
    ],
)
def test_gemini_errors_are_clear_and_never_leak_the_key(resp: httpx.Response, message: str):
    with pytest.raises(AIError) as e:
        GeminiProvider("SECRETKEY", "m", _mock(lambda r: resp)).generate("s", "p", "low")
    assert str(e.value) == message
    assert "SECRETKEY" not in str(e.value)


def test_openai_and_anthropic_request_shapes() -> None:
    seen: list[httpx.Request] = []

    def openai(req: httpx.Request) -> httpx.Response:
        seen.append(req)
        return httpx.Response(
            200,
            json={
                "output": [{"type": "message", "content": [{"type": "output_text", "text": "OK"}]}]
            },
        )

    assert OpenAIProvider("K", "m", _mock(openai)).generate("s", "p", "high").text == "OK"
    assert seen[-1].headers["authorization"] == "Bearer K"
    assert json.loads(seen[-1].content)["reasoning"] == {"effort": "high"}

    def anthropic(req: httpx.Request) -> httpx.Response:
        seen.append(req)
        return httpx.Response(200, json={"content": [{"type": "text", "text": "Hi"}]})

    assert (
        AnthropicProvider("K2", "claude-x", _mock(anthropic)).generate("s", "p", "low").text == "Hi"
    )
    assert seen[-1].headers["x-api-key"] == "K2"


def test_provider_selection() -> None:
    assert isinstance(provider_for(Settings(env="test")), FakeProvider)
    with pytest.raises(AIError, match="needs an API key"):
        provider_for(Settings(env="test", ai_provider="gemini", gemini_api_key=""))
    g = provider_for(Settings(env="test", ai_provider="gemini", gemini_api_key="k"))
    assert isinstance(g, GeminiProvider) and g.model == "gemini-4-argon"


# --- Drafts --------------------------------------------------------------------------------------


def test_draft_lifecycle(session: Session, user: User) -> None:
    incident = _incident(session)
    case = next(c for c in incident.cases if c.site.business_name == SECRET_NAME)
    draft = ai.create_draft(session, case, user, FakeProvider(), "high")
    assert SECRET_NAME in draft.content  # filled in by Protect, not by the AI
    assert "Darshan" in draft.content and "{{CLIENT_NAME}}" in draft.content
    assert case.client_notice is ClientNotice.DRAFTED
    with pytest.raises(ai.DraftError, match="Fill in before approving"):
        ai.approve_draft(session, case, draft, user)
    with pytest.raises(ai.DraftError, match="Approve the message"):
        ai.mark_sent(session, case, draft, user)

    filled = draft.content.replace("{{CLIENT_NAME}}", "Ravi").replace("{{FIX_TIME}}", "23 Oct")
    ai.save_draft(session, case, draft, user, filled)
    ai.approve_draft(session, case, draft, user)
    assert case.client_notice is ClientNotice.APPROVED
    ai.save_draft(session, case, draft, user, filled + "\nP.S.")  # editing undoes approval
    assert draft.approved_at is None
    ai.approve_draft(session, case, draft, user)
    ai.mark_sent(session, case, draft, user)
    assert case.client_notice is ClientNotice.SENT and draft.sent_at is not None
    with pytest.raises(ai.DraftError):
        ai.save_draft(session, case, draft, user, "changed after sending")


def test_one_draft_per_case(session: Session, user: User) -> None:
    case = _incident(session).cases[0]
    ai.create_draft(session, case, user, FakeProvider(), "high")
    with pytest.raises(ai.DraftError):
        ai.create_draft(session, case, user, FakeProvider(), "high")


def test_drafts_share_one_ai_call_per_incident(session: Session, user: User) -> None:
    incident = _incident(session)
    p = CountingProvider()
    for case in incident.cases:
        ai.create_draft(session, case, user, p, "high")
    assert len(p.calls) == 1 and len(incident.cases) == 2


@pytest.mark.parametrize(
    "claim", ["Your site is now unhackable.", "fully protected", "No data was accessed."]
)
def test_overclaims_block_approval(session: Session, user: User, claim: str) -> None:
    case = _incident(session).cases[0]
    draft = ai.create_draft(session, case, user, CountingProvider("Hi Ravi. " + claim), "high")
    with pytest.raises(ai.DraftError, match="we never promise security"):
        ai.approve_draft(session, case, draft, user)


def test_drill_draft_must_keep_its_label(session: Session, user: User) -> None:
    case = _incident(session, "drill-plugin").cases[0]
    draft = ai.create_draft(session, case, user, FakeProvider(), "high")
    assert draft.content.startswith("[DRILL]")
    ai.save_draft(session, case, draft, user, "Hi Ravi, all fixed. Darshan")
    with pytest.raises(ai.DraftError, match="keep the \\[DRILL\\] line"):
        ai.approve_draft(session, case, draft, user)


# --- Dashboard -----------------------------------------------------------------------------------


def _dash(db_url: str, provider):  # type: ignore[no-untyped-def]
    dash = make_dash(db_url)
    dash.client.app.state.ai_provider_factory = lambda settings: provider  # type: ignore[attr-defined]
    with dash.session() as s:
        incident = _incident(s)
        s.commit()
        return dash, incident.id, incident.cases[0].id


def test_summary_button_and_escaping(db_url: str) -> None:
    dash, incident_id, _ = _dash(db_url, CountingProvider("<script>alert(1)</script>\n- point"))
    dash.login()
    page = f"/incidents/{incident_id}"
    r = dash.post(f"{page}/ai-summary", page=page)
    assert r.status_code == 303
    text = dash.client.get(page).text
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in text and "<script>alert" not in text
    assert "counting / count-1" in text and "no site details" in text


def test_ai_errors_show_on_the_page(db_url: str) -> None:
    class Down:
        name, model = "gemini", "gemini-4-argon"

        def generate(self, *a: str) -> AIText:
            raise AIError("Gemini returned HTTP 503.")

    dash, incident_id, _ = _dash(db_url, Down())
    dash.login()
    r = dash.post(f"/incidents/{incident_id}/ai-summary", page=f"/incidents/{incident_id}")
    assert r.status_code == 400 and "Gemini returned HTTP 503." in r.text


def test_case_draft_flow_in_the_dashboard(db_url: str) -> None:
    dash, _, case_id = _dash(db_url, FakeProvider())
    dash.login(UserRole.VIEWER)
    assert (
        dash.post(
            f"/cases/{case_id}/draft", {"action": "create"}, page=f"/cases/{case_id}"
        ).status_code
        == 403
    )
    dash.client.cookies.clear()
    dash.login(UserRole.RESPONDER, "Darshan")
    page = f"/cases/{case_id}"
    assert dash.post(f"{page}/draft", {"action": "create"}, page=page).status_code == 303
    text = dash.client.get(page).text
    assert "Fill in before approving" in text and "{{CLIENT_NAME}}" in text
    assert dash.post(f"{page}/draft", {"action": "approve"}, page=page).status_code == 400
    content = re.search(r'<textarea name="content"[^>]*>(.*?)</textarea>', text, re.S)
    assert content
    filled = (
        content.group(1)
        .replace("{{CLIENT_NAME}}", "Ravi")
        .replace("{{FIX_TIME}}", "23 Oct")
        .replace("&#39;", "'")
    )
    assert (
        dash.post(f"{page}/draft", {"action": "save", "content": filled}, page=page).status_code
        == 303
    )
    assert dash.post(f"{page}/draft", {"action": "approve"}, page=page).status_code == 303
    assert dash.post(f"{page}/draft", {"action": "sent"}, page=page).status_code == 303
    assert "Marked as sent" in dash.client.get(page).text
