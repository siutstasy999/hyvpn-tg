"""End-to-end handler tests: real dispatcher, fake Telegram transport."""

from __future__ import annotations

import asyncio
import re
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest
from aiogram import Bot
from aiogram.client.session.base import BaseSession
from aiogram.methods import TelegramMethod
from aiogram.methods.base import Response
from aiogram.types import CallbackQuery, Chat, Message, Update, User

from bot.main import build_dispatcher, commands_for
from bot.services import CertWatcher, LangStore, LiveStats
from core.cert_service import CertInfo
from core.config import BotSettings
from core.db import connect
from core.keys_service import create_key, get_key, limit_of

OWNER = 1000
STRANGER = 2000
CHAT_ID = 777
GB = 1024**3


class FakeSession(BaseSession):
    """Records outgoing API calls and answers them with plausible results."""

    def __init__(self) -> None:
        super().__init__()
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self._message_id = 100

    async def close(self) -> None:  # pragma: no cover - nothing to close
        return None

    async def stream_content(self, *args, **kwargs):  # pragma: no cover
        yield b""

    async def make_request(self, bot: Bot, method: TelegramMethod, timeout=None):
        name = type(method).__name__
        payload = method.model_dump(exclude_none=True)
        self.calls.append((name, payload))

        if name == "GetMe":
            return User(id=1, is_bot=True, first_name="hy", username="hy_bot")
        if name in {"SendMessage", "EditMessageText", "SendPhoto"}:
            self._message_id += 1
            return Message(
                message_id=self._message_id,
                date=datetime.now(timezone.utc),
                chat=Chat(id=CHAT_ID, type="private"),
                text=payload.get("text") or payload.get("caption") or "",
            )
        return True

    def check_response(self, *args, **kwargs):  # pragma: no cover - unused
        return Response(ok=True, result=True)

    def texts(self, *methods: str) -> list[str]:
        wanted = methods or ("SendMessage", "EditMessageText", "SendPhoto")
        return [
            payload.get("text") or payload.get("caption") or ""
            for name, payload in self.calls
            if name in wanted
        ]

    def names(self) -> list[str]:
        return [name for name, _ in self.calls]


class FixedCerts(CertWatcher):
    """CertWatcher that never touches the filesystem."""

    def __init__(self, info: CertInfo):
        self._info = info

    async def get(self, force: bool = False) -> CertInfo:
        return self._info


def make_settings(db_path: Path, **overrides) -> BotSettings:
    values = {
        "BOT_TOKEN": "123456:TEST",
        "ALLOWED_TG_IDS": str(OWNER),
        "DATABASE_PATH": str(db_path),
        "SERVER_DOMAIN": "my-own.online",
        "SERVER_PORT": 443,
        "LOCATION_NAME": "🇫🇮 Finland",
        "DEFAULT_LANG": "ru",
        "HYSTERIA_STATS_SECRET": "",
    }
    values.update(overrides)
    return BotSettings(**values)


def user(user_id: int) -> User:
    return User(id=user_id, is_bot=False, first_name="U")


def message_update(text: str, user_id: int = OWNER, update_id: int = 1) -> Update:
    return Update(
        update_id=update_id,
        message=Message(
            message_id=update_id,
            date=datetime.now(timezone.utc),
            chat=Chat(id=CHAT_ID, type="private"),
            from_user=user(user_id),
            text=text,
        ),
    )


def callback_update(data: str, user_id: int = OWNER, update_id: int = 1) -> Update:
    return Update(
        update_id=update_id,
        callback_query=CallbackQuery(
            id=str(update_id),
            from_user=user(user_id),
            chat_instance="ci",
            data=data,
            message=Message(
                message_id=50,
                date=datetime.now(timezone.utc),
                chat=Chat(id=CHAT_ID, type="private"),
                text="previous screen",
            ),
        ),
    )


class Harness:
    def __init__(self, db_path: Path, cert: CertInfo | None = None, **overrides):
        self.settings = make_settings(db_path, **overrides)
        self.session = FakeSession()
        self.bot = Bot(token=self.settings.bot_token, session=self.session)
        self.certs = FixedCerts(cert or CertInfo(domain="my-own.online"))
        self.langs = LangStore(self.settings)
        self.dispatcher = build_dispatcher(
            self.settings, LiveStats(self.settings), self.certs, self.langs
        )

    async def feed(self, update: Update) -> None:
        await self.dispatcher.feed_update(self.bot, update)

    def reset(self) -> None:
        self.session.calls.clear()

    def last(self) -> str:
        texts = self.session.texts()
        return texts[0] if texts else ""


def run(scenario, **kwargs) -> None:
    async def wrapper():
        with tempfile.TemporaryDirectory() as td:
            harness = Harness(Path(td) / "db.sqlite3", **kwargs)
            try:
                await scenario(harness)
            finally:
                await harness.bot.session.close()

    asyncio.run(wrapper())


async def seed_key(harness: Harness, label: str = "Ключ", limit: int = 0) -> str:
    db = await connect(harness.settings.database_path)
    try:
        created = await create_key(
            db, label, OWNER, "my-own.online", 443, limit, "🇫🇮 Finland"
        )
    finally:
        await db.close()
    return created["id"]


# --------------------------------------------------------------------------- #
# access control
# --------------------------------------------------------------------------- #

def test_stranger_is_rejected_and_learns_own_id():
    async def scenario(h: Harness):
        await h.feed(message_update("/start", user_id=STRANGER))
        text = "\n".join(h.session.texts())
        assert "Доступ запрещён" in text
        assert str(STRANGER) in text
        assert "hysteria2://" not in text

        h.reset()
        await h.feed(callback_update("keys:1:act", user_id=STRANGER))
        assert h.session.names() == ["AnswerCallbackQuery"]

    run(scenario)


def test_empty_whitelist_denies_everyone():
    async def scenario(h: Harness):
        await h.feed(message_update("/start"))
        assert "Доступ запрещён" in "\n".join(h.session.texts())

    run(scenario, ALLOWED_TG_IDS="")


def test_bad_allowed_ids_is_reported():
    settings = BotSettings(
        BOT_TOKEN="123456:TEST",
        ALLOWED_TG_IDS="123,oops",
        SERVER_DOMAIN="my-own.online",
    )
    with pytest.raises(ValueError, match="ALLOWED_TG_IDS"):
        _ = settings.allowed_ids


# --------------------------------------------------------------------------- #
# navigation
# --------------------------------------------------------------------------- #

def test_menu_and_navigation():
    async def scenario(h: Harness):
        await h.feed(message_update("/start"))
        assert "Finland" in h.last()

        for data, expected in (
            ("keys:1:act", "Пока нет ни одного ключа"),
            ("stats", "Данных пока нет"),
            ("help", "Как подключиться"),
            ("server", "TLS-сертификат"),
            ("lang", "Язык интерфейса"),
            ("menu", "Ключей:"),
        ):
            h.reset()
            await h.feed(callback_update(data))
            assert expected in h.last(), data

    run(scenario)


def test_certificate_state_is_shown():
    fresh = CertInfo(
        domain="my-own.online",
        not_after=datetime.now(timezone.utc) + timedelta(days=70),
        issuer="Let's Encrypt",
        source="snapshot",
    )

    async def scenario(h: Harness):
        await h.feed(callback_update("server"))
        text = h.last()
        assert "Действует до" in text
        assert "Let&#x27;s Encrypt" in text or "Let's Encrypt" in text

    run(scenario, cert=fresh)


def test_expiring_certificate_is_flagged():
    soon = CertInfo(
        domain="my-own.online",
        not_after=datetime.now(timezone.utc) + timedelta(days=3),
        source="snapshot",
    )

    async def scenario(h: Harness):
        await h.feed(callback_update("server"))
        assert "Истекает" in h.last()
        h.reset()
        await h.feed(callback_update("menu"))
        assert "⚠️" in h.last()

    run(scenario, cert=soon)


def test_unknown_certificate_does_not_break_screens():
    async def scenario(h: Harness):
        await h.feed(callback_update("server"))
        assert "Неизвестно" in h.last()

    run(scenario)


# --------------------------------------------------------------------------- #
# language
# --------------------------------------------------------------------------- #

def test_language_switch_persists():
    async def scenario(h: Harness):
        await h.feed(callback_update("setlang:en"))
        assert "Keys:" in h.last()

        # The choice survives the next update...
        h.reset()
        await h.feed(message_update("/keys"))
        assert "No keys yet" in h.last()

        # ...and a bot restart, because it is stored in SQLite.
        h.langs._cache.clear()
        h.reset()
        await h.feed(message_update("/start"))
        assert "Keys:" in h.last()

        h.reset()
        await h.feed(callback_update("setlang:ru"))
        assert "Ключей:" in h.last()

    run(scenario)


def test_default_language_can_be_english():
    async def scenario(h: Harness):
        await h.feed(message_update("/start"))
        assert "Keys:" in h.last()

    run(scenario, DEFAULT_LANG="en")


def test_command_menu_is_translated():
    ru = {command.command: command.description for command in commands_for("ru")}
    en = {command.command: command.description for command in commands_for("en")}
    assert set(ru) == set(en)
    assert ru["start"] != en["start"]


# --------------------------------------------------------------------------- #
# keys
# --------------------------------------------------------------------------- #

def test_created_uri_is_human_readable_and_has_no_label():
    async def scenario(h: Harness):
        await h.feed(message_update("/new Иван — iPhone"))
        text = h.last()
        assert "Ключ создан" in text
        assert "Иван — iPhone" in text  # the label is shown as a field

        match = re.search(r"<code>(hysteria2://[^<]+)</code>", text)
        assert match, text
        uri = match.group(1)
        # No percent-encoded bytes anywhere in the link.
        assert "%" not in uri
        # The profile name is the location, not the key label.
        assert uri.endswith("#🇫🇮 Finland")
        assert "Иван" not in uri
        assert "iPhone" not in uri

    run(scenario)


def test_create_key_via_button_flow():
    async def scenario(h: Harness):
        await h.feed(callback_update("new"))
        assert "Как назвать ключ" in h.last()

        h.reset()
        await h.feed(message_update("Ноутбук"))
        assert "Ключ создан" in h.last()

        h.reset()
        await h.feed(callback_update("keys:1:act"))
        assert "Ноутбук" in h.last()

    run(scenario)


def test_key_card_rename_and_revoke():
    async def scenario(h: Harness):
        key_id = await seed_key(h, "Старое имя")

        await h.feed(callback_update(f"key:{key_id}"))
        card = h.last()
        assert "Старое имя" in card
        assert "hysteria2://" in card
        assert "Активен" in card

        h.reset()
        await h.feed(callback_update(f"ren:{key_id}"))
        assert "Переименование" in h.last()
        h.reset()
        await h.feed(message_update("Новое имя"))
        assert any("Новое имя" in text for text in h.session.texts())

        h.reset()
        await h.feed(callback_update(f"askrev:{key_id}"))
        assert "Отозвать ключ?" in h.last()

        h.reset()
        await h.feed(callback_update(f"dorev:{key_id}"))
        assert "Ключ отозван" in h.last()

        # A revoked key no longer exposes its URI and cannot be revoked twice.
        h.reset()
        await h.feed(callback_update(f"key:{key_id}"))
        card = h.last()
        assert "Отозван" in card
        assert "hysteria2://" not in card

        h.reset()
        await h.feed(callback_update(f"dorev:{key_id}"))
        assert h.session.names() == ["AnswerCallbackQuery"]

    run(scenario)


def test_qr_is_sent_as_photo():
    async def scenario(h: Harness):
        key_id = await seed_key(h, "QR")
        await h.feed(callback_update(f"qr:{key_id}"))
        assert "SendPhoto" in h.session.names()

    run(scenario)


def test_unknown_key_id_does_not_crash():
    async def scenario(h: Harness):
        await h.feed(callback_update("key:does-not-exist"))
        assert h.session.names() == ["AnswerCallbackQuery"]
        assert h.session.calls[0][1].get("text") == "Ключ не найден"

    run(scenario)


def test_revoke_command_requires_id():
    async def scenario(h: Harness):
        await h.feed(message_update("/revoke"))
        assert "Укажите ID ключа" in h.last()

        h.reset()
        await h.feed(message_update("/revoke nope"))
        assert "не найден" in h.last()

    run(scenario)


# --------------------------------------------------------------------------- #
# traffic limits
# --------------------------------------------------------------------------- #

def test_traffic_limit_can_be_set_and_removed():
    async def scenario(h: Harness):
        key_id = await seed_key(h, "Квота")

        await h.feed(callback_update(f"key:{key_id}"))
        assert "не задан" in h.last()

        h.reset()
        await h.feed(callback_update(f"lim:{key_id}"))
        assert "Лимит трафика" in h.last()

        h.reset()
        await h.feed(message_update("50 GB"))
        assert any("50.00 ГБ" in text for text in h.session.texts())

        db = await connect(h.settings.database_path)
        try:
            assert limit_of(await get_key(db, key_id)) == 50 * GB
        finally:
            await db.close()

        h.reset()
        await h.feed(callback_update(f"limoff:{key_id}"))
        db = await connect(h.settings.database_path)
        try:
            assert limit_of(await get_key(db, key_id)) == 0
        finally:
            await db.close()

    run(scenario)


def test_bare_number_is_read_as_gigabytes():
    async def scenario(h: Harness):
        key_id = await seed_key(h)
        await h.feed(callback_update(f"lim:{key_id}"))
        h.reset()
        await h.feed(message_update("100"))

        db = await connect(h.settings.database_path)
        try:
            assert limit_of(await get_key(db, key_id)) == 100 * GB
        finally:
            await db.close()

    run(scenario)


def test_invalid_limit_keeps_asking():
    async def scenario(h: Harness):
        key_id = await seed_key(h, limit=GB)
        await h.feed(callback_update(f"lim:{key_id}"))
        h.reset()
        await h.feed(message_update("много"))
        assert "Не понял размер" in h.last()

        # Still in the limit dialog: a valid value now works.
        h.reset()
        await h.feed(message_update("2 GB"))
        db = await connect(h.settings.database_path)
        try:
            assert limit_of(await get_key(db, key_id)) == 2 * GB
        finally:
            await db.close()

    run(scenario)


def test_key_over_quota_is_shown_as_blocked():
    async def scenario(h: Harness):
        key_id = await seed_key(h, "Исчерпан", limit=GB)
        db = await connect(h.settings.database_path)
        try:
            await db.execute(
                "UPDATE keys SET download_total = ? WHERE id = ?", (2 * GB, key_id)
            )
            await db.commit()
        finally:
            await db.close()

        await h.feed(callback_update(f"key:{key_id}"))
        assert "Заблокирован" in h.last()

    run(scenario)
