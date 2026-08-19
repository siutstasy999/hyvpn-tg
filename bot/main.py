"""Entry point for hy-bot: aiogram long polling with an inline-keyboard UI."""

from __future__ import annotations

import asyncio
import logging
import sys

from aiogram import Bot, Dispatcher
from aiogram.client.default import DefaultBotProperties
from aiogram.enums import ParseMode
from aiogram.fsm.storage.memory import MemoryStorage
from aiogram.types import BotCommand, BotCommandScopeDefault, ErrorEvent

from core.config import get_bot_settings

from . import services
from .handlers import build_router
from .i18n import COMMAND_DESCRIPTIONS, LANGS, normalize_lang, t
from .middlewares import LanguageMiddleware, WhitelistMiddleware

log = logging.getLogger("hy-bot")

COMMAND_ORDER = ("start", "new", "keys", "stats", "server", "lang", "help", "id")


def commands_for(lang: str) -> list[BotCommand]:
    descriptions = COMMAND_DESCRIPTIONS[normalize_lang(lang)]
    return [
        BotCommand(command=name, description=descriptions[name])
        for name in COMMAND_ORDER
    ]


def build_dispatcher(
    settings,
    live: services.LiveStats,
    certs: services.CertWatcher | None = None,
    langs: services.LangStore | None = None,
) -> Dispatcher:
    certs = certs or services.CertWatcher(settings)
    langs = langs or services.LangStore(settings)

    dispatcher = Dispatcher(
        storage=MemoryStorage(),
        settings=settings,
        live=live,
        certs=certs,
        langs=langs,
    )

    guard = WhitelistMiddleware(settings.allowed_ids, langs)
    language = LanguageMiddleware(langs)
    for observer in (dispatcher.message, dispatcher.callback_query):
        observer.outer_middleware(guard)
        observer.outer_middleware(language)
    dispatcher.include_router(build_router())

    @dispatcher.errors()
    async def on_error(event: ErrorEvent) -> bool:
        log.exception("handler failed: %s", event.exception)
        message = getattr(event.update, "message", None)
        callback = getattr(event.update, "callback_query", None)
        lang = langs.default
        try:
            if callback is not None:
                await callback.answer(t(lang, "toast_error"), show_alert=True)
            elif message is not None:
                await message.answer(t(lang, "err_internal"))
        except Exception:  # pragma: no cover - best-effort notification
            log.debug("could not deliver the error notice", exc_info=True)
        return True

    return dispatcher


async def run() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
    )

    settings = get_bot_settings()
    allowed = settings.allowed_ids
    if not allowed:
        log.error(
            "ALLOWED_TG_IDS is empty: nobody can use the bot. "
            "Send /start to the bot, take the ID it replies with, put it into "
            "ALLOWED_TG_IDS in /etc/hyvpn/.env.bot and restart hy-bot."
        )

    live = services.LiveStats(settings)
    if not live.enabled:
        log.warning(
            "HYSTERIA_STATS_SECRET is not set for the bot: online status and "
            "unflushed traffic will be hidden."
        )
    if not services.QR_AVAILABLE:
        log.warning("qrcode/Pillow is not installed: QR code buttons are hidden.")

    certs = services.CertWatcher(settings)
    cert = await certs.get()
    if cert.known:
        log.info("certificate for %s expires in %s day(s)", cert.domain, cert.days_left)
    else:
        log.warning("certificate state unknown: %s", cert.error)

    bot = Bot(
        token=settings.bot_token,
        default=DefaultBotProperties(
            parse_mode=ParseMode.HTML,
            link_preview_is_disabled=True,
        ),
    )
    dispatcher = build_dispatcher(settings, live, certs)

    me = await bot.get_me()
    await _publish_commands(bot, settings.default_lang)
    log.info(
        "hy-bot started as @%s · %s allowed user(s) · server %s:%s",
        me.username,
        len(allowed),
        settings.server_domain,
        settings.server_port,
    )

    try:
        await dispatcher.start_polling(
            bot, allowed_updates=["message", "callback_query"]
        )
    finally:
        await bot.session.close()


async def _publish_commands(bot: Bot, default_lang: str) -> None:
    """Register the command menu for every supported language."""
    default_lang = normalize_lang(default_lang)
    await bot.set_my_commands(
        commands_for(default_lang), scope=BotCommandScopeDefault()
    )
    for lang in LANGS:
        try:
            await bot.set_my_commands(
                commands_for(lang), scope=BotCommandScopeDefault(), language_code=lang
            )
        except Exception as exc:  # pragma: no cover - Telegram may reject a code
            log.warning("could not publish %s commands: %s", lang, exc)


def main() -> None:
    try:
        asyncio.run(run())
    except KeyboardInterrupt:
        log.info("hy-bot stopped")
    except Exception as exc:
        log.critical("hy-bot could not start: %s", exc, exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
