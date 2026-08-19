"""All bot handlers. The UI is a single message the user navigates in place."""

from __future__ import annotations

import logging

from aiogram import F, Router
from aiogram.exceptions import TelegramBadRequest
from aiogram.filters import Command, CommandStart
from aiogram.fsm.context import FSMContext
from aiogram.fsm.state import State, StatesGroup
from aiogram.types import BufferedInputFile, CallbackQuery, Message

from core.config import BotSettings
from core.keys_service import (
    create_key,
    get_key,
    limit_of,
    rename_key,
    revoke_key,
    set_traffic_limit,
)
from core.uri import build_uri

from . import services, ui
from .i18n import parse_size, t

log = logging.getLogger(__name__)

MAX_LABEL = 64


class NewKey(StatesGroup):
    label = State()


class RenameKey(StatesGroup):
    label = State()


class LimitKey(StatesGroup):
    value = State()


# --------------------------------------------------------------------------- #
# low-level helpers
# --------------------------------------------------------------------------- #

async def _edit(call: CallbackQuery, text: str, keyboard) -> None:
    """Replace the screen the user is looking at.

    Photo messages (QR codes) cannot become text messages, so they are
    replaced with a fresh message instead of edited.
    """
    message = call.message
    if message is None:
        return
    if message.photo:
        try:
            await message.delete()
        except TelegramBadRequest:
            pass
        await message.answer(text, reply_markup=keyboard)
        return
    try:
        await message.edit_text(text, reply_markup=keyboard)
    except TelegramBadRequest as exc:
        if "message is not modified" not in str(exc):
            raise


def _uri_for(row, settings: BotSettings) -> str:
    # The profile name is the server location, never the key label: the same
    # server should look the same in every client.
    return build_uri(
        row["password"],
        settings.server_domain,
        settings.server_port,
        settings.profile_name,
    )


def _clean_label(raw: str | None) -> str:
    return " ".join((raw or "").split())[:MAX_LABEL]


# --------------------------------------------------------------------------- #
# screen renderers
# --------------------------------------------------------------------------- #

async def _menu_screen(
    lang: str,
    settings: BotSettings,
    live: services.LiveStats,
    certs: services.CertWatcher,
) -> tuple[str, object]:
    async with services.db_session(settings) as db:
        summary = await services.totals(db)

    online_map = await live.online()
    online = sum(online_map.values()) if live.enabled else None

    text = ui.screen_menu(
        lang,
        location=settings.profile_name,
        domain=settings.server_domain,
        port=settings.server_port,
        active=summary["active"],
        revoked=summary["revoked"],
        online=online,
        upload=summary["upload"],
        download=summary["download"],
        cert=await certs.get(),
    )
    return text, ui.kb_main(lang)


async def _keys_screen(
    lang: str, settings: BotSettings, page: int, show_all: bool
) -> tuple[str, object]:
    async with services.db_session(settings) as db:
        rows, page, pages = await services.keys_page(db, page, ui.PAGE_SIZE, show_all)
    return (
        ui.screen_keys(lang, rows, page, pages, show_all),
        ui.kb_keys(lang, rows, page, pages, show_all),
    )


async def _key_screen(
    lang: str, settings: BotSettings, live: services.LiveStats, key_id: str
) -> tuple[str, object] | None:
    async with services.db_session(settings) as db:
        row = await get_key(db, key_id)
    if row is None:
        return None

    online_map = await live.online()
    pending = (await live.pending()).get(str(key_id))

    text = ui.screen_key(
        lang,
        row,
        uri=_uri_for(row, settings),
        location=settings.profile_name,
        online=online_map.get(str(key_id), 0),
        pending_upload=pending.upload if pending else 0,
        pending_download=pending.download if pending else 0,
    )
    keyboard = ui.kb_key(
        lang, key_id, bool(row["is_active"]), with_qr=services.QR_AVAILABLE
    )
    return text, keyboard


async def _stats_screen(
    lang: str, settings: BotSettings, live: services.LiveStats
) -> tuple[str, object]:
    async with services.db_session(settings) as db:
        rows = await services.stats_rows(db)
    online_map = await live.online()
    return (
        ui.screen_stats(lang, rows, settings.profile_name, online_map),
        ui.kb_back(lang, "menu"),
    )


async def _server_screen(
    lang: str,
    settings: BotSettings,
    live: services.LiveStats,
    certs: services.CertWatcher,
) -> tuple[str, object]:
    async with services.db_session(settings) as db:
        summary = await services.totals(db)
    online_map = await live.online()
    text = ui.screen_server(
        lang,
        domain=settings.server_domain,
        port=settings.server_port,
        active=summary["active"],
        revoked=summary["revoked"],
        online=sum(online_map.values()) if live.enabled else None,
        traffic=summary["upload"] + summary["download"],
        cert=await certs.get(),
    )
    return text, ui.kb_back(lang, "menu")


async def _send_new_key(
    message: Message, lang: str, settings: BotSettings, label: str
) -> None:
    async with services.db_session(settings) as db:
        created = await create_key(
            db,
            label=label,
            owner_tg_id=message.from_user.id if message.from_user else None,
            server_domain=settings.server_domain,
            server_port=settings.server_port,
            profile_name=settings.profile_name,
        )

    await message.answer(
        ui.screen_created(
            lang,
            label=created["label"],
            key_id=created["id"],
            uri=created["uri"] or "",
            location=settings.profile_name,
        ),
        reply_markup=ui.kb_after_create(
            lang, created["id"], services.QR_AVAILABLE
        ),
    )


async def _show_card(
    message: Message,
    lang: str,
    settings: BotSettings,
    live: services.LiveStats,
    key_id: str,
) -> None:
    screen = await _key_screen(lang, settings, live, key_id)
    if screen is None:
        await message.answer(
            t(lang, "toast_not_found"), reply_markup=ui.kb_back(lang, "menu")
        )
        return
    await message.answer(screen[0], reply_markup=screen[1])


# --------------------------------------------------------------------------- #
# commands
# --------------------------------------------------------------------------- #

async def cmd_start(
    message: Message,
    state: FSMContext,
    lang: str,
    settings: BotSettings,
    live: services.LiveStats,
    certs: services.CertWatcher,
) -> None:
    await state.clear()
    text, keyboard = await _menu_screen(lang, settings, live, certs)
    await message.answer(text, reply_markup=keyboard)


async def cmd_help(message: Message, lang: str) -> None:
    await message.answer(ui.screen_help(lang), reply_markup=ui.kb_back(lang, "menu"))


async def cmd_id(message: Message, lang: str) -> None:
    user_id = message.from_user.id if message.from_user else 0
    await message.answer(t(lang, "my_id", id=user_id))


async def cmd_lang(message: Message, state: FSMContext, lang: str) -> None:
    await state.clear()
    await message.answer(ui.screen_lang(lang), reply_markup=ui.kb_lang(lang))


async def cmd_keys(
    message: Message, state: FSMContext, lang: str, settings: BotSettings
) -> None:
    await state.clear()
    text, keyboard = await _keys_screen(lang, settings, 1, show_all=False)
    await message.answer(text, reply_markup=keyboard)


async def cmd_stats(
    message: Message,
    state: FSMContext,
    lang: str,
    settings: BotSettings,
    live: services.LiveStats,
) -> None:
    await state.clear()
    text, keyboard = await _stats_screen(lang, settings, live)
    await message.answer(text, reply_markup=keyboard)


async def cmd_server(
    message: Message,
    state: FSMContext,
    lang: str,
    settings: BotSettings,
    live: services.LiveStats,
    certs: services.CertWatcher,
) -> None:
    await state.clear()
    text, keyboard = await _server_screen(lang, settings, live, certs)
    await message.answer(text, reply_markup=keyboard)


async def cmd_new(
    message: Message, state: FSMContext, lang: str, settings: BotSettings
) -> None:
    parts = (message.text or "").split(maxsplit=1)
    label = _clean_label(parts[1] if len(parts) > 1 else "")
    if not label:
        await state.set_state(NewKey.label)
        await message.answer(
            ui.screen_new_prompt(lang), reply_markup=ui.kb_cancel(lang)
        )
        return
    await _send_new_key(message, lang, settings, label)


async def cmd_revoke(message: Message, lang: str, settings: BotSettings) -> None:
    parts = (message.text or "").split(maxsplit=1)
    if len(parts) < 2 or not parts[1].strip():
        await message.answer(t(lang, "revoke_cmd_usage"))
        return

    key_id = parts[1].strip()
    async with services.db_session(settings) as db:
        ok = await revoke_key(db, key_id)
    key = "revoke_cmd_done" if ok else "revoke_cmd_missing"
    await message.answer(t(lang, key, id=ui.esc(key_id)))


# --------------------------------------------------------------------------- #
# FSM input
# --------------------------------------------------------------------------- #

async def input_new_label(
    message: Message, state: FSMContext, lang: str, settings: BotSettings
) -> None:
    label = _clean_label(message.text)
    if not label:
        await message.answer(t(lang, "empty_input"), reply_markup=ui.kb_cancel(lang))
        return
    await state.clear()
    await _send_new_key(message, lang, settings, label)


async def input_rename_label(
    message: Message,
    state: FSMContext,
    lang: str,
    settings: BotSettings,
    live: services.LiveStats,
) -> None:
    label = _clean_label(message.text)
    if not label:
        await message.answer(t(lang, "empty_input"), reply_markup=ui.kb_cancel(lang))
        return

    key_id = (await state.get_data()).get("key_id")
    await state.clear()
    if not key_id:
        await message.answer(
            t(lang, "toast_not_found"), reply_markup=ui.kb_back(lang, "menu")
        )
        return

    async with services.db_session(settings) as db:
        ok = await rename_key(db, key_id, label)
    if not ok:
        await message.answer(
            t(lang, "toast_not_found"), reply_markup=ui.kb_back(lang, "menu")
        )
        return

    await message.answer(t(lang, "renamed", label=ui.esc(label)))
    await _show_card(message, lang, settings, live, key_id)


async def input_limit(
    message: Message,
    state: FSMContext,
    lang: str,
    settings: BotSettings,
    live: services.LiveStats,
) -> None:
    limit = parse_size(message.text)
    if limit is None:
        await message.answer(t(lang, "limit_bad"), reply_markup=ui.kb_cancel(lang))
        return

    key_id = (await state.get_data()).get("key_id")
    await state.clear()
    if not key_id:
        await message.answer(
            t(lang, "toast_not_found"), reply_markup=ui.kb_back(lang, "menu")
        )
        return

    async with services.db_session(settings) as db:
        ok = await set_traffic_limit(db, key_id, limit)
    if not ok:
        await message.answer(
            t(lang, "toast_not_found"), reply_markup=ui.kb_back(lang, "menu")
        )
        return

    if limit == 0:
        await message.answer(t(lang, "limit_cleared"))
    else:
        await message.answer(
            t(lang, "limit_set", value=ui.fmt_bytes(lang, limit))
        )
    await _show_card(message, lang, settings, live, key_id)


# --------------------------------------------------------------------------- #
# callbacks
# --------------------------------------------------------------------------- #

async def cb_noop(call: CallbackQuery) -> None:
    await call.answer()


async def cb_menu(
    call: CallbackQuery,
    state: FSMContext,
    lang: str,
    settings: BotSettings,
    live: services.LiveStats,
    certs: services.CertWatcher,
) -> None:
    await state.clear()
    text, keyboard = await _menu_screen(lang, settings, live, certs)
    await _edit(call, text, keyboard)
    await call.answer()


async def cb_cancel(call: CallbackQuery, state: FSMContext, lang: str) -> None:
    await state.clear()
    await _edit(call, t(lang, "cancelled"), ui.kb_back(lang, "menu"))
    await call.answer()


async def cb_help(call: CallbackQuery, lang: str) -> None:
    await _edit(call, ui.screen_help(lang), ui.kb_back(lang, "menu"))
    await call.answer()


async def cb_stats(
    call: CallbackQuery, lang: str, settings: BotSettings, live: services.LiveStats
) -> None:
    text, keyboard = await _stats_screen(lang, settings, live)
    await _edit(call, text, keyboard)
    await call.answer()


async def cb_server(
    call: CallbackQuery,
    lang: str,
    settings: BotSettings,
    live: services.LiveStats,
    certs: services.CertWatcher,
) -> None:
    text, keyboard = await _server_screen(lang, settings, live, certs)
    await _edit(call, text, keyboard)
    await call.answer()


async def cb_lang(call: CallbackQuery, state: FSMContext, lang: str) -> None:
    await state.clear()
    await _edit(call, ui.screen_lang(lang), ui.kb_lang(lang))
    await call.answer()


async def cb_set_lang(
    call: CallbackQuery,
    settings: BotSettings,
    live: services.LiveStats,
    certs: services.CertWatcher,
    langs: services.LangStore,
) -> None:
    requested = call.data.split(":", 1)[1]
    lang = await langs.set(call.from_user.id, requested)
    text, keyboard = await _menu_screen(lang, settings, live, certs)
    await _edit(call, text, keyboard)
    await call.answer(t(lang, "lang_saved"))


async def cb_keys(
    call: CallbackQuery, state: FSMContext, lang: str, settings: BotSettings
) -> None:
    await state.clear()
    _, raw_page, mode = call.data.split(":", 2)
    try:
        page = int(raw_page)
    except ValueError:
        page = 1
    text, keyboard = await _keys_screen(lang, settings, page, show_all=(mode == "all"))
    await _edit(call, text, keyboard)
    await call.answer()


async def cb_new(call: CallbackQuery, state: FSMContext, lang: str) -> None:
    await state.set_state(NewKey.label)
    await _edit(call, ui.screen_new_prompt(lang), ui.kb_cancel(lang))
    await call.answer()


async def cb_key(
    call: CallbackQuery,
    state: FSMContext,
    lang: str,
    settings: BotSettings,
    live: services.LiveStats,
) -> None:
    await state.clear()
    key_id = call.data.split(":", 1)[1]
    screen = await _key_screen(lang, settings, live, key_id)
    if screen is None:
        await call.answer(t(lang, "toast_not_found"), show_alert=True)
        return
    await _edit(call, screen[0], screen[1])
    await call.answer()


async def cb_qr(call: CallbackQuery, lang: str, settings: BotSettings) -> None:
    key_id = call.data.split(":", 1)[1]
    async with services.db_session(settings) as db:
        row = await get_key(db, key_id)

    if row is None:
        await call.answer(t(lang, "toast_not_found"), show_alert=True)
        return
    if not row["is_active"]:
        await call.answer(t(lang, "toast_revoked"), show_alert=True)
        return

    image = services.render_qr(_uri_for(row, settings))
    if image is None:
        await call.answer(t(lang, "toast_qr_off"), show_alert=True)
        return

    await call.message.answer_photo(
        BufferedInputFile(image.read(), filename=f"hyvpn-{ui.short_id(key_id)}.png"),
        caption=t(lang, "qr_caption", label=ui.esc(row["label"])),
        reply_markup=ui.kb_key(lang, key_id, True, with_qr=False),
    )
    await call.answer()


async def cb_rename(call: CallbackQuery, state: FSMContext, lang: str) -> None:
    key_id = call.data.split(":", 1)[1]
    await state.set_state(RenameKey.label)
    await state.update_data(key_id=key_id)
    await _edit(call, ui.screen_rename_prompt(lang), ui.kb_cancel(lang))
    await call.answer()


async def cb_limit(
    call: CallbackQuery, state: FSMContext, lang: str, settings: BotSettings
) -> None:
    key_id = call.data.split(":", 1)[1]
    async with services.db_session(settings) as db:
        row = await get_key(db, key_id)
    if row is None:
        await call.answer(t(lang, "toast_not_found"), show_alert=True)
        return

    await state.set_state(LimitKey.value)
    await state.update_data(key_id=key_id)
    await _edit(
        call,
        ui.screen_limit_prompt(lang, row),
        ui.kb_limit(lang, key_id, limit_of(row) > 0),
    )
    await call.answer()


async def cb_limit_off(
    call: CallbackQuery,
    state: FSMContext,
    lang: str,
    settings: BotSettings,
    live: services.LiveStats,
) -> None:
    key_id = call.data.split(":", 1)[1]
    await state.clear()
    async with services.db_session(settings) as db:
        ok = await set_traffic_limit(db, key_id, 0)
    if not ok:
        await call.answer(t(lang, "toast_not_found"), show_alert=True)
        return

    screen = await _key_screen(lang, settings, live, key_id)
    if screen is not None:
        await _edit(call, screen[0], screen[1])
    await call.answer(t(lang, "limit_cleared"))


async def cb_revoke_confirm(
    call: CallbackQuery, lang: str, settings: BotSettings
) -> None:
    key_id = call.data.split(":", 1)[1]
    async with services.db_session(settings) as db:
        row = await get_key(db, key_id)
    if row is None:
        await call.answer(t(lang, "toast_not_found"), show_alert=True)
        return

    await _edit(
        call, ui.screen_revoke_confirm(lang, row), ui.kb_confirm_revoke(lang, key_id)
    )
    await call.answer()


async def cb_revoke_do(call: CallbackQuery, lang: str, settings: BotSettings) -> None:
    key_id = call.data.split(":", 1)[1]
    async with services.db_session(settings) as db:
        ok = await revoke_key(db, key_id)

    if not ok:
        await call.answer(t(lang, "toast_already_revoked"), show_alert=True)
        return

    await _edit(
        call,
        ui.screen_revoked(lang, key_id),
        ui.kb_back(lang, "keys:1:act", "btn_back_list"),
    )
    await call.answer(t(lang, "toast_revoked"))


# --------------------------------------------------------------------------- #
# fallback
# --------------------------------------------------------------------------- #

async def fallback(
    message: Message,
    lang: str,
    settings: BotSettings,
    live: services.LiveStats,
    certs: services.CertWatcher,
) -> None:
    text, keyboard = await _menu_screen(lang, settings, live, certs)
    await message.answer(text, reply_markup=keyboard)


# --------------------------------------------------------------------------- #
# routing table
# --------------------------------------------------------------------------- #

def build_router() -> Router:
    """Build a fresh router. Prefixes must stay mutually exclusive."""
    router = Router(name="hyvpn")

    router.message.register(cmd_start, CommandStart())
    router.message.register(cmd_start, Command("menu"))
    router.message.register(cmd_help, Command("help"))
    router.message.register(cmd_id, Command("id"))
    router.message.register(cmd_lang, Command("lang", "language"))
    router.message.register(cmd_keys, Command("keys", "list"))
    router.message.register(cmd_stats, Command("stats"))
    router.message.register(cmd_server, Command("server", "status"))
    router.message.register(cmd_new, Command("new", "newkey"))
    router.message.register(cmd_revoke, Command("revoke", "delkey"))

    router.message.register(input_new_label, NewKey.label)
    router.message.register(input_rename_label, RenameKey.label)
    router.message.register(input_limit, LimitKey.value)

    router.callback_query.register(cb_noop, F.data == "noop")
    router.callback_query.register(cb_menu, F.data == "menu")
    router.callback_query.register(cb_cancel, F.data == "cancel")
    router.callback_query.register(cb_help, F.data == "help")
    router.callback_query.register(cb_stats, F.data == "stats")
    router.callback_query.register(cb_server, F.data == "server")
    router.callback_query.register(cb_lang, F.data == "lang")
    router.callback_query.register(cb_set_lang, F.data.startswith("setlang:"))
    router.callback_query.register(cb_keys, F.data.startswith("keys:"))
    router.callback_query.register(cb_new, F.data == "new")
    router.callback_query.register(cb_key, F.data.startswith("key:"))
    router.callback_query.register(cb_qr, F.data.startswith("qr:"))
    router.callback_query.register(cb_rename, F.data.startswith("ren:"))
    router.callback_query.register(cb_limit, F.data.startswith("lim:"))
    router.callback_query.register(cb_limit_off, F.data.startswith("limoff:"))
    router.callback_query.register(cb_revoke_confirm, F.data.startswith("askrev:"))
    router.callback_query.register(cb_revoke_do, F.data.startswith("dorev:"))

    # Anything else from a whitelisted user simply shows the menu.
    router.message.register(fallback)
    return router
