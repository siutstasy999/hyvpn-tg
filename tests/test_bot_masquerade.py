"""The masquerade section of the bot: screens, buttons, permissions."""

from __future__ import annotations

import asyncio
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from aiogram import Bot

from bot import ui
from bot.main import build_dispatcher
from bot.services import LangStore, LiveStats
from core.cert_service import CertInfo
from core.masquerade.selector import Plan
from tests.masq_fakes import evaluation, status_view
from tests.test_bot_flow import (
    STRANGER,
    FakeSession,
    FixedCerts,
    callback_update,
    make_settings,
    message_update,
)

NOW = datetime.now(timezone.utc).isoformat()


class FakeMasq:
    """Duck-typed MasqWatcher: no filesystem, no network, no threads."""

    def __init__(self, *, status=None, report=None, plan=None, results=None):
        self._status = status or status_view(evaluations=[evaluation("own-site")])
        self.report = report or {
            "ok": True,
            "problems": [],
            "warnings": [],
            "notes": ["fragment mode: proxy", "service is active"],
        }
        self.plan_obj = plan or Plan(
            mode="proxy",
            candidate=None,
            reason="own candidate is healthy; keeping it",
            changed=False,
            previous_mode="proxy",
            previous_candidate="own-site",
            evaluations=[evaluation("own-site")],
        )
        self._results = results or []
        self.status_calls = 0
        self.test_calls = 0
        self.submitted: list[tuple[str, dict]] = []

    async def status(self, force: bool = False):
        self.status_calls += 1
        return self._status

    async def check(self) -> dict:
        return self.report

    async def test_candidates(self):
        self.test_calls += 1
        return [evaluation("own-site")]

    async def plan(self):
        return self.plan_obj

    async def submit(self, kind: str, payload=None, requested_by=None) -> str:
        self.submitted.append((kind, payload or {}))
        return "req0001"

    async def results(self, limit: int = 3):
        return self._results


class MasqHarness:
    def __init__(self, db_path: Path, *, masq=None, lang: str = "ru", **overrides):
        self.settings = make_settings(db_path, **overrides)
        self.session = FakeSession()
        self.bot = Bot(token=self.settings.bot_token, session=self.session)
        self.certs = FixedCerts(CertInfo(domain="my-own.online"))
        self.langs = LangStore(self.settings)
        self.masq = masq or FakeMasq()
        self.dispatcher = build_dispatcher(
            self.settings, LiveStats(self.settings), self.certs, self.langs, self.masq
        )

    async def feed(self, update):
        await self.dispatcher.feed_update(self.bot, update)

    def reset(self):
        self.session.calls.clear()

    def last(self) -> str:
        texts = self.session.texts()
        return texts[0] if texts else ""


def run(scenario, *, masq=None, **overrides) -> None:
    async def wrapper():
        with tempfile.TemporaryDirectory() as td:
            harness = MasqHarness(Path(td) / "db.sqlite3", masq=masq, **overrides)
            try:
                await scenario(harness)
            finally:
                await harness.bot.session.close()

    asyncio.run(wrapper())


# --------------------------------------------------------------------------- #
# access control
# --------------------------------------------------------------------------- #

def test_a_stranger_cannot_open_the_masquerade_screen():
    async def scenario(h: MasqHarness):
        await h.feed(callback_update("masq", user_id=STRANGER))
        # Only the denial toast is sent; no server-side information leaks.
        assert h.session.names() == ["AnswerCallbackQuery"]
        assert "Доступ запрещён" in str(h.session.calls[0][1].get("text"))
        assert h.masq.status_calls == 0

    run(scenario)


def test_a_stranger_cannot_queue_an_apply():
    async def scenario(h: MasqHarness):
        await h.feed(callback_update("masq:apply", user_id=STRANGER))
        await h.feed(callback_update("masq:set:file", user_id=STRANGER))
        assert h.masq.submitted == []

    run(scenario)


# --------------------------------------------------------------------------- #
# screens and buttons
# --------------------------------------------------------------------------- #

def buttons(harness: MasqHarness) -> list[dict]:
    """Every inline button of the last message that carried a keyboard."""
    for _name, payload in reversed(harness.session.calls):
        markup = payload.get("reply_markup")
        if markup:
            return [button for row in markup["inline_keyboard"] for button in row]
    return []


def test_the_server_screen_links_to_the_masquerade():
    async def scenario(h: MasqHarness):
        await h.feed(callback_update("server"))
        found = buttons(h)
        assert any(button["callback_data"] == "masq" for button in found)
        assert any("Маскарад" in button["text"] for button in found)

    run(scenario)


def test_the_status_screen_shows_mode_upstream_and_health():
    async def scenario(h: MasqHarness):
        await h.feed(callback_update("masq"))
        text = h.last()
        assert "Маскарад" in text
        assert "proxy" in text
        assert "own-site.example" in text
        assert "healthy" in text
        assert "Кандидаты" in text

    run(scenario)


def test_status_screen_without_an_upstream_says_so():
    masq = FakeMasq(
        status=status_view(
            effective_mode="file", upstream=None, candidate_id=None, candidate_health="unknown"
        )
    )

    async def scenario(h: MasqHarness):
        await h.feed(callback_update("masq"))
        assert "локальный сайт" in h.last()

    run(scenario, masq=masq)


def test_check_button_shows_the_diagnostic_notes():
    async def scenario(h: MasqHarness):
        await h.feed(callback_update("masq:check"))
        text = h.last()
        assert "Проверка маскарада" in text
        assert "Проблем не найдено" in text
        assert "fragment mode: proxy" in text

    run(scenario)


def test_check_button_shows_problems():
    masq = FakeMasq(
        report={
            "ok": False,
            "problems": ["masquerade.proxy.insecure must stay false"],
            "warnings": ["fallback site is missing"],
            "notes": [],
        }
    )

    async def scenario(h: MasqHarness):
        await h.feed(callback_update("masq:check"))
        text = h.last()
        assert "Найдены проблемы" in text
        assert "insecure" in text
        assert "fallback site is missing" in text

    run(scenario, masq=masq)


def test_candidate_test_runs_off_the_event_loop_and_reports():
    async def scenario(h: MasqHarness):
        await h.feed(callback_update("masq:test"))
        assert h.masq.test_calls == 1
        assert "own-site" in h.last()

    run(scenario)


def test_optimize_shows_the_proposal_without_applying_it():
    plan = Plan(
        mode="file",
        candidate=None,
        reason="own-site is not usable; serving the local fallback site",
        changed=True,
        previous_mode="proxy",
        previous_candidate="own-site",
        evaluations=[evaluation("own-site", eligible=False, health="unhealthy")],
    )
    masq = FakeMasq(plan=plan)

    async def scenario(h: MasqHarness):
        await h.feed(callback_update("masq:plan"))
        text = h.last()
        assert "Предлагаемая конфигурация" in text
        assert "proxy" in text and "file" in text
        assert "локальный" in h.last() or "fallback" in h.last()
        assert any(
            button["callback_data"] == "masq:apply" for button in buttons(h)
        )
        assert masq.submitted == []

    run(scenario, masq=masq)


def test_apply_is_queued_not_executed():
    async def scenario(h: MasqHarness):
        await h.feed(callback_update("masq:apply"))
        assert h.masq.submitted == [("optimize", {})]
        assert "очередь" in h.last().lower() or "Задача" in h.last()

    run(scenario)


def test_mode_selection_queues_a_set_mode_request():
    async def scenario(h: MasqHarness):
        await h.feed(callback_update("masq:modes"))
        assert "Режим маскарада" in h.last()
        h.reset()
        await h.feed(callback_update("masq:set:file"))
        assert h.masq.submitted == [("set-mode", {"mode": "file"})]

    run(scenario)


def test_an_unknown_mode_is_refused():
    async def scenario(h: MasqHarness):
        await h.feed(callback_update("masq:set:carrier-pigeon"))
        assert h.masq.submitted == []
        assert h.session.names() == ["AnswerCallbackQuery"]

    run(scenario)


def test_results_screen_lists_recent_deployments():
    masq = FakeMasq(
        results=[
            {
                "request": {"kind": "optimize"},
                "result": {"ok": True, "action": "optimize"},
                "finished_at": NOW,
            },
            {
                "request": {"kind": "set-mode"},
                "result": {"ok": False, "action": "set-mode", "error": "unit did not start"},
                "finished_at": NOW,
            },
        ]
    )

    async def scenario(h: MasqHarness):
        await h.feed(callback_update("masq:results"))
        text = h.last()
        assert "optimize" in text
        assert "set-mode" in text
        assert "unit did not start" in text

    run(scenario, masq=masq)


def test_english_screen_is_translated():
    async def scenario(h: MasqHarness):
        await h.feed(callback_update("setlang:en"))
        h.reset()
        await h.feed(callback_update("masq"))
        text = h.last()
        assert "masquerade" in text.lower()
        assert "Candidates" in text

    run(scenario)


def test_the_masq_command_opens_the_screen():
    async def scenario(h: MasqHarness):
        await h.feed(message_update("/masq"))
        assert "Маскарад" in h.last()

    run(scenario)


def test_ui_renders_every_health_state():
    for health, icon in (
        ("healthy", "✅"),
        ("degraded", "⚠️"),
        ("unhealthy", "🔴"),
        ("unknown", "⚪️"),
    ):
        status = status_view(candidate_health=health)
        text = ui.screen_masquerade("en", status)
        assert icon in text
