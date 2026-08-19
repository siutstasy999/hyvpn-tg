"""Bot middlewares: access control and language resolution."""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable
from typing import Any

from aiogram import BaseMiddleware
from aiogram.types import CallbackQuery, Message, TelegramObject

from . import ui
from .i18n import t
from .services import LangStore

log = logging.getLogger(__name__)


class WhitelistMiddleware(BaseMiddleware):
    """Drop every update whose author is not in ``ALLOWED_TG_IDS``.

    An empty whitelist denies everybody: an open VPN key issuer is worse than
    a bot nobody can talk to. Rejected users only ever learn their own
    Telegram ID, which is what they need to be added by the owner.
    """

    def __init__(self, allowed_ids: set[int], langs: LangStore):
        self.allowed_ids = allowed_ids
        self.langs = langs
        super().__init__()

    async def __call__(
        self,
        handler: Callable[[TelegramObject, dict[str, Any]], Awaitable[Any]],
        event: TelegramObject,
        data: dict[str, Any],
    ) -> Any:
        user = data.get("event_from_user")
        if user is not None and user.id in self.allowed_ids:
            return await handler(event, data)

        user_id = user.id if user else 0
        log.warning("rejected update from tg_id=%s", user_id)

        lang = self.langs.default
        if isinstance(event, Message):
            await event.answer(ui.screen_unauthorized(lang, user_id))
        elif isinstance(event, CallbackQuery):
            await event.answer(t(lang, "toast_denied"), show_alert=True)
        return None


class LanguageMiddleware(BaseMiddleware):
    """Inject the operator's interface language as ``lang``."""

    def __init__(self, langs: LangStore):
        self.langs = langs
        super().__init__()

    async def __call__(
        self,
        handler: Callable[[TelegramObject, dict[str, Any]], Awaitable[Any]],
        event: TelegramObject,
        data: dict[str, Any],
    ) -> Any:
        user = data.get("event_from_user")
        data["lang"] = (
            await self.langs.get(user.id) if user is not None else self.langs.default
        )
        return await handler(event, data)
