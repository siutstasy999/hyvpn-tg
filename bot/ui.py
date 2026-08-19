"""Presentation layer: text formatting and inline keyboards, per language."""

from __future__ import annotations

import html
from datetime import datetime, timezone

from aiogram.types import InlineKeyboardButton, InlineKeyboardMarkup
from aiogram.utils.keyboard import InlineKeyboardBuilder

from core.cert_service import CertInfo
from core.keys_service import limit_of, used_bytes

from .i18n import LANG_LABELS, LANGS, RULE, t, units

PAGE_SIZE = 6
CERT_WARN_DAYS = 14


# --------------------------------------------------------------------------- #
# formatting helpers
# --------------------------------------------------------------------------- #

def esc(value: object) -> str:
    """HTML-escape any value so user labels cannot break the message."""
    return html.escape(str(value if value is not None else ""), quote=False)


def fmt_bytes(lang: str, size: float | int | None) -> str:
    names = units(lang)
    value = float(size or 0)
    for index, unit in enumerate(names):
        if abs(value) < 1024.0 or index == len(names) - 1:
            if index == 0:
                return f"{value:.0f} {unit}"
            return f"{value:.2f} {unit}"
        value /= 1024.0
    return f"{value:.2f} {names[-1]}"  # pragma: no cover - loop always returns


def parse_dt(raw: str | None) -> datetime | None:
    if not raw:
        return None
    try:
        parsed = datetime.fromisoformat(raw)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def fmt_dt(raw: str | datetime | None) -> str:
    parsed = raw if isinstance(raw, datetime) else parse_dt(raw)
    if parsed is None:
        return "—"
    return parsed.astimezone(timezone.utc).strftime("%d.%m.%Y %H:%M UTC")


def fmt_date(raw: str | datetime | None) -> str:
    parsed = raw if isinstance(raw, datetime) else parse_dt(raw)
    if parsed is None:
        return "—"
    return parsed.astimezone(timezone.utc).strftime("%d.%m.%Y")


def fmt_ago(lang: str, raw: str | None) -> str:
    parsed = parse_dt(raw)
    if parsed is None:
        return t(lang, "ago_never")
    seconds = max(int((datetime.now(timezone.utc) - parsed).total_seconds()), 0)
    if seconds < 60:
        return t(lang, "ago_now")
    if seconds < 3600:
        return t(lang, "ago_min", n=seconds // 60)
    if seconds < 86400:
        return t(lang, "ago_hour", n=seconds // 3600)
    return t(lang, "ago_day", n=seconds // 86400)


def short_id(key_id: str) -> str:
    return str(key_id).split("-")[0]


def progress_bar(part: int, whole: int, width: int = 10) -> str:
    if whole <= 0:
        return "░" * width
    filled = max(0, min(width, round(width * part / whole)))
    return "█" * filled + "░" * (width - filled)


def cert_short(lang: str, cert: CertInfo | None) -> str:
    """One-line certificate status for the main menu."""
    if cert is None or not cert.known:
        return t(lang, "cert_short_unknown")
    days = cert.days_left or 0
    if cert.expired:
        return t(lang, "cert_short_expired")
    if days <= CERT_WARN_DAYS:
        return t(lang, "cert_short_soon", days=days)
    return t(lang, "cert_short_ok", date=fmt_date(cert.not_after), days=days)


def cert_line(lang: str, cert: CertInfo | None) -> str:
    """Full certificate status for the server screen."""
    if cert is None or not cert.known:
        error = cert.error if cert else ""
        return t(lang, "server_cert_unknown", error=esc(error or "no data"))
    days = cert.days_left or 0
    date = fmt_date(cert.not_after)
    if cert.expired:
        return t(lang, "server_cert_expired", date=date)
    if days <= CERT_WARN_DAYS:
        return t(lang, "server_cert_soon", date=date, days=days)
    return t(lang, "server_cert_ok", date=date, days=days)


def limit_line(lang: str, row) -> str:
    limit = limit_of(row)
    if limit <= 0:
        return t(lang, "card_limit_none")
    used = used_bytes(row)
    percent = min(100, int(used * 100 / limit)) if limit else 0
    return t(
        lang,
        "card_limit",
        used=fmt_bytes(lang, used),
        limit=fmt_bytes(lang, limit),
        percent=percent,
        bar=f"<code>{progress_bar(used, limit)}</code>",
    )


# --------------------------------------------------------------------------- #
# screens
# --------------------------------------------------------------------------- #

def screen_menu(
    lang: str,
    *,
    location: str,
    domain: str,
    port: int,
    active: int,
    revoked: int,
    online: int | None,
    upload: int,
    download: int,
    cert: CertInfo | None = None,
) -> str:
    online_line = (
        t(lang, "menu_online_unknown")
        if online is None
        else t(lang, "menu_online", n=online)
    )
    return "\n".join(
        [
            t(lang, "menu_title", location=esc(location or domain)),
            f"<code>{esc(domain)}:{port}</code>",
            RULE,
            t(lang, "menu_keys", active=active, revoked=revoked),
            online_line,
            t(
                lang,
                "menu_traffic",
                up=fmt_bytes(lang, upload),
                down=fmt_bytes(lang, download),
            ),
            t(lang, "menu_cert", cert=cert_short(lang, cert)),
            RULE,
            t(lang, "menu_hint"),
        ]
    )


def screen_keys(lang: str, rows: list, page: int, pages: int, show_all: bool) -> str:
    title = t(lang, "keys_title_all" if show_all else "keys_title_active")
    if not rows:
        return f"{title}\n{RULE}\n{t(lang, 'keys_empty')}"

    header = title + t(lang, "keys_page", page=page, pages=pages)
    lines = [header, RULE]
    for row in rows:
        total = used_bytes(row)
        limit = limit_of(row)
        if not row["is_active"]:
            badge = "⚫️"
        elif limit and total >= limit:
            badge = "🔴"
        else:
            badge = "🟢"
        quota = f" / {fmt_bytes(lang, limit)}" if limit else ""
        lines.append(
            f"{badge} <b>{esc(row['label'])}</b>\n"
            f"    <code>{short_id(row['id'])}</code>"
            f" · 📦 {fmt_bytes(lang, total)}{quota}"
            f" · 🕒 {fmt_ago(lang, row['last_seen_at'])}"
        )
    lines += [RULE, t(lang, "keys_hint")]
    return "\n".join(lines)


def screen_key(
    lang: str,
    row,
    *,
    uri: str,
    location: str,
    online: int | None,
    pending_upload: int = 0,
    pending_download: int = 0,
) -> str:
    limit = limit_of(row)
    total = used_bytes(row)
    blocked = bool(row["is_active"]) and limit > 0 and total >= limit

    if not row["is_active"]:
        status = t(lang, "card_revoked", date=fmt_dt(row["revoked_at"]))
    elif blocked:
        status = t(lang, "card_blocked")
    else:
        status = t(lang, "card_active")
        if online:
            status += t(lang, "card_online", n=online)

    lines = [
        f"<b>🔑 {esc(row['label'])}</b>",
        RULE,
        status,
        t(lang, "card_id", id=esc(row["id"])),
        t(lang, "card_created", date=fmt_dt(row["created_at"])),
        t(lang, "card_seen", ago=fmt_ago(lang, row["last_seen_at"])),
        "",
        t(lang, "card_up", value=fmt_bytes(lang, row["upload_total"] or 0)),
        t(lang, "card_down", value=fmt_bytes(lang, row["download_total"] or 0)),
        t(lang, "card_total", value=fmt_bytes(lang, total)),
        limit_line(lang, row),
    ]

    pending = pending_upload + pending_download
    if pending > 0:
        lines.append(t(lang, "card_pending", value=fmt_bytes(lang, pending)))

    if row["is_active"]:
        suffix = f" · {esc(location)}" if location else ""
        lines += [
            "",
            t(lang, "card_link", suffix=suffix),
            f"<code>{esc(uri)}</code>",
            "",
            t(lang, "card_copy_hint"),
        ]
    else:
        lines += ["", t(lang, "card_revoked_note")]

    return "\n".join(lines)


def screen_stats(
    lang: str, rows: list, location: str, online_map: dict[str, int]
) -> str:
    title = t(lang, "stats_title", suffix=f" · {esc(location)}" if location else "")
    if not rows:
        return f"{title}\n{RULE}\n{t(lang, 'stats_empty')}"

    total_upload = sum(row["upload_total"] or 0 for row in rows)
    total_download = sum(row["download_total"] or 0 for row in rows)
    top = max(used_bytes(row) for row in rows)

    lines = [title, RULE]
    for row in rows[:20]:
        key_total = used_bytes(row)
        badge = "🟢" if online_map.get(str(row["id"]), 0) > 0 else "▫️"
        limit = limit_of(row)
        bar = progress_bar(key_total, limit or top)
        quota = f" / {fmt_bytes(lang, limit)}" if limit else ""
        lines.append(
            f"{badge} <b>{esc(row['label'])}</b> — "
            f"{fmt_bytes(lang, key_total)}{quota}\n    <code>{bar}</code>"
        )

    if len(rows) > 20:
        lines.append(t(lang, "stats_more", n=len(rows) - 20))

    lines += [
        RULE,
        t(lang, "stats_up", value=fmt_bytes(lang, total_upload)),
        t(lang, "stats_down", value=fmt_bytes(lang, total_download)),
        t(lang, "stats_total", value=fmt_bytes(lang, total_upload + total_download)),
    ]
    return "\n".join(lines)


def screen_server(
    lang: str,
    *,
    domain: str,
    port: int,
    active: int,
    revoked: int,
    online: int | None,
    traffic: int,
    cert: CertInfo | None,
) -> str:
    online_line = (
        t(lang, "server_online_unknown")
        if online is None
        else t(lang, "server_online", n=online)
    )
    lines = [
        t(lang, "server_title"),
        RULE,
        t(lang, "server_address", domain=esc(domain), port=port),
        online_line,
        t(lang, "server_keys", active=active, revoked=revoked),
        t(lang, "server_traffic", value=fmt_bytes(lang, traffic)),
        "",
        t(lang, "server_cert_title"),
        cert_line(lang, cert),
    ]
    if cert is not None and cert.issuer:
        lines.append(t(lang, "server_cert_issuer", issuer=esc(cert.issuer)))
    lines += ["", t(lang, "server_cert_hint")]
    return "\n".join(lines)


def screen_help(lang: str) -> str:
    return "\n".join(
        [
            t(lang, "help_title"),
            RULE,
            t(lang, "help_commands"),
            RULE,
            t(lang, "help_connect"),
            RULE,
            t(lang, "help_note"),
        ]
    )


def screen_new_prompt(lang: str) -> str:
    return f"{t(lang, 'new_title')}\n{RULE}\n{t(lang, 'new_prompt')}"


def screen_created(lang: str, *, label: str, key_id: str, uri: str, location: str) -> str:
    suffix = f" · {esc(location)}" if location else ""
    return "\n".join(
        [
            t(lang, "new_created"),
            RULE,
            t(lang, "new_label", label=esc(label), suffix=suffix),
            t(lang, "card_id", id=esc(key_id)),
            "",
            t(lang, "card_link", suffix=""),
            f"<code>{esc(uri)}</code>",
            "",
            t(lang, "new_hint"),
        ]
    )


def screen_rename_prompt(lang: str) -> str:
    return f"{t(lang, 'rename_title')}\n{RULE}\n{t(lang, 'rename_prompt')}"


def screen_limit_prompt(lang: str, row) -> str:
    limit = limit_of(row)
    current = fmt_bytes(lang, limit) if limit else t(lang, "unlimited")
    return "\n".join(
        [
            t(lang, "limit_title"),
            RULE,
            f"<b>{esc(row['label'])}</b>",
            t(lang, "limit_current", value=current),
            "",
            t(lang, "limit_prompt"),
        ]
    )


def screen_revoke_confirm(lang: str, row) -> str:
    return "\n".join(
        [
            t(lang, "revoke_title"),
            RULE,
            f"🏷 <b>{esc(row['label'])}</b>",
            t(lang, "card_id", id=esc(row["id"])),
            "",
            t(lang, "revoke_warning"),
        ]
    )


def screen_revoked(lang: str, key_id: str) -> str:
    return "\n".join(
        [t(lang, "revoked_done"), RULE, t(lang, "card_id", id=esc(key_id))]
    )


def screen_lang(lang: str) -> str:
    return f"{t(lang, 'lang_title')}\n{RULE}\n{t(lang, 'lang_prompt')}"


def screen_unauthorized(lang: str, user_id: int) -> str:
    return t(lang, "unauthorized", id=user_id)


# --------------------------------------------------------------------------- #
# keyboards
# --------------------------------------------------------------------------- #

def kb_main(lang: str) -> InlineKeyboardMarkup:
    builder = InlineKeyboardBuilder()
    builder.button(text=t(lang, "btn_keys"), callback_data="keys:1:act")
    builder.button(text=t(lang, "btn_new"), callback_data="new")
    builder.button(text=t(lang, "btn_stats"), callback_data="stats")
    builder.button(text=t(lang, "btn_server"), callback_data="server")
    builder.button(text=t(lang, "btn_help"), callback_data="help")
    builder.button(text=t(lang, "btn_lang"), callback_data="lang")
    builder.button(text=t(lang, "btn_refresh"), callback_data="menu")
    builder.adjust(2, 2, 2, 1)
    return builder.as_markup()


def kb_keys(
    lang: str, rows: list, page: int, pages: int, show_all: bool
) -> InlineKeyboardMarkup:
    builder = InlineKeyboardBuilder()
    mode = "all" if show_all else "act"

    for row in rows:
        limit = limit_of(row)
        if not row["is_active"]:
            badge = "⚫️"
        elif limit and used_bytes(row) >= limit:
            badge = "🔴"
        else:
            badge = "🟢"
        builder.row(
            InlineKeyboardButton(
                text=f"{badge} {row['label']}"[:64],
                callback_data=f"key:{row['id']}",
            )
        )

    nav: list[InlineKeyboardButton] = []
    if page > 1:
        nav.append(
            InlineKeyboardButton(text="◀️", callback_data=f"keys:{page - 1}:{mode}")
        )
    if pages > 1:
        nav.append(InlineKeyboardButton(text=f"{page}/{pages}", callback_data="noop"))
    if page < pages:
        nav.append(
            InlineKeyboardButton(text="▶️", callback_data=f"keys:{page + 1}:{mode}")
        )
    if nav:
        builder.row(*nav)

    toggle = "btn_only_active" if show_all else "btn_show_revoked"
    builder.row(
        InlineKeyboardButton(
            text=t(lang, toggle),
            callback_data=f"keys:1:{'act' if show_all else 'all'}",
        )
    )
    builder.row(
        InlineKeyboardButton(text=t(lang, "btn_new"), callback_data="new"),
        InlineKeyboardButton(text=t(lang, "btn_menu"), callback_data="menu"),
    )
    return builder.as_markup()


def kb_key(
    lang: str,
    key_id: str,
    is_active: bool,
    *,
    back: str = "keys:1:act",
    with_qr: bool = True,
) -> InlineKeyboardMarkup:
    builder = InlineKeyboardBuilder()
    if is_active:
        first_row = []
        if with_qr:
            first_row.append(
                InlineKeyboardButton(text=t(lang, "btn_qr"), callback_data=f"qr:{key_id}")
            )
        first_row.append(
            InlineKeyboardButton(
                text=t(lang, "btn_rename"), callback_data=f"ren:{key_id}"
            )
        )
        builder.row(*first_row)
        builder.row(
            InlineKeyboardButton(
                text=t(lang, "btn_limit"), callback_data=f"lim:{key_id}"
            )
        )
        builder.row(
            InlineKeyboardButton(
                text=t(lang, "btn_revoke"), callback_data=f"askrev:{key_id}"
            )
        )
    builder.row(
        InlineKeyboardButton(text=t(lang, "btn_refresh"), callback_data=f"key:{key_id}"),
        InlineKeyboardButton(text=t(lang, "btn_back_list"), callback_data=back),
    )
    builder.row(InlineKeyboardButton(text=t(lang, "btn_menu"), callback_data="menu"))
    return builder.as_markup()


def kb_confirm_revoke(lang: str, key_id: str) -> InlineKeyboardMarkup:
    builder = InlineKeyboardBuilder()
    builder.row(
        InlineKeyboardButton(
            text=t(lang, "btn_revoke_yes"), callback_data=f"dorev:{key_id}"
        ),
        InlineKeyboardButton(text=t(lang, "btn_cancel"), callback_data=f"key:{key_id}"),
    )
    return builder.as_markup()


def kb_back(lang: str, target: str = "menu", key: str = "btn_menu") -> InlineKeyboardMarkup:
    builder = InlineKeyboardBuilder()
    builder.row(InlineKeyboardButton(text=t(lang, key), callback_data=target))
    return builder.as_markup()


def kb_cancel(lang: str, target: str = "cancel") -> InlineKeyboardMarkup:
    builder = InlineKeyboardBuilder()
    builder.row(InlineKeyboardButton(text=t(lang, "btn_cancel"), callback_data=target))
    return builder.as_markup()


def kb_limit(lang: str, key_id: str, has_limit: bool) -> InlineKeyboardMarkup:
    builder = InlineKeyboardBuilder()
    if has_limit:
        builder.row(
            InlineKeyboardButton(
                text=t(lang, "btn_limit_off"), callback_data=f"limoff:{key_id}"
            )
        )
    builder.row(
        InlineKeyboardButton(text=t(lang, "btn_cancel"), callback_data=f"key:{key_id}")
    )
    return builder.as_markup()


def kb_after_create(lang: str, key_id: str, with_qr: bool = True) -> InlineKeyboardMarkup:
    builder = InlineKeyboardBuilder()
    top = []
    if with_qr:
        top.append(
            InlineKeyboardButton(text=t(lang, "btn_qr"), callback_data=f"qr:{key_id}")
        )
    top.append(
        InlineKeyboardButton(text=t(lang, "btn_card"), callback_data=f"key:{key_id}")
    )
    builder.row(*top)
    builder.row(
        InlineKeyboardButton(text=t(lang, "btn_new_more"), callback_data="new"),
        InlineKeyboardButton(text=t(lang, "btn_menu"), callback_data="menu"),
    )
    return builder.as_markup()


def kb_lang(lang: str) -> InlineKeyboardMarkup:
    builder = InlineKeyboardBuilder()
    for code in LANGS:
        mark = "✅ " if code == lang else ""
        builder.row(
            InlineKeyboardButton(
                text=f"{mark}{LANG_LABELS[code]}", callback_data=f"setlang:{code}"
            )
        )
    builder.row(InlineKeyboardButton(text=t(lang, "btn_menu"), callback_data="menu"))
    return builder.as_markup()
