"""Bot translations. Every language must define exactly the same keys.

`tests/test_i18n.py` fails if a key is missing from one of the languages, so a
new string cannot be added to one language only.
"""

from __future__ import annotations

import re

LANGS: tuple[str, ...] = ("ru", "en")
FALLBACK_LANG = "ru"

LANG_LABELS = {"ru": "🇷🇺 Русский", "en": "🇬🇧 English"}

RULE = "──────────────────"

TEXTS: dict[str, dict[str, str]] = {
    "ru": {
        # units and relative time
        "units": "Б,КБ,МБ,ГБ,ТБ,ПБ",
        "ago_never": "ни разу",
        "ago_now": "только что",
        "ago_min": "{n} мин назад",
        "ago_hour": "{n} ч назад",
        "ago_day": "{n} дн назад",
        "unlimited": "без лимита",
        # buttons
        "btn_keys": "🔑 Ключи",
        "btn_new": "➕ Новый ключ",
        "btn_new_more": "➕ Ещё ключ",
        "btn_stats": "📊 Статистика",
        "btn_server": "🖥 Сервер",
        "btn_help": "ℹ️ Справка",
        "btn_lang": "🌐 Язык",
        "btn_refresh": "🔄 Обновить",
        "btn_menu": "🏠 Меню",
        "btn_back_list": "⬅️ К списку",
        "btn_card": "🔑 Карточка ключа",
        "btn_qr": "📱 QR-код",
        "btn_rename": "✏️ Переименовать",
        "btn_limit": "📦 Лимит трафика",
        "btn_revoke": "🗑 Отозвать ключ",
        "btn_revoke_yes": "✅ Да, отозвать",
        "btn_cancel": "❌ Отмена",
        "btn_show_revoked": "👁 Показать отозванные",
        "btn_only_active": "👁 Только активные",
        "btn_limit_off": "♾ Снять лимит",
        # main menu
        "menu_title": "🛡 {location}",
        "menu_keys": "🔑 <b>Ключей:</b> {active} активных · {revoked} отозванных",
        "menu_online": "🟢 <b>Онлайн сейчас:</b> {n} устройств(а)",
        "menu_online_unknown": "⚪️ <i>Статус онлайн недоступен</i>",
        "menu_traffic": "📦 <b>Трафик:</b> ⬆️ {up} · ⬇️ {down}",
        "menu_cert": "📜 <b>Сертификат:</b> {cert}",
        "menu_hint": "<i>Выберите действие ниже.</i>",
        # key list
        "keys_title_active": "🔑 <b>Ключи</b> · активные",
        "keys_title_all": "🔑 <b>Ключи</b> · все",
        "keys_page": " · стр. {page}/{pages}",
        "keys_empty": (
            "📭 <i>Пока нет ни одного ключа.</i>\n\n"
            "Нажмите <b>➕ Новый ключ</b>, чтобы создать первый."
        ),
        "keys_hint": "<i>Нажмите на ключ, чтобы открыть карточку.</i>",
        # key card
        "card_active": "🟢 <b>Активен</b>",
        "card_online": " · 📱 {n} устройств(а) онлайн",
        "card_revoked": "⚫️ <b>Отозван</b> · {date}",
        "card_blocked": "🔴 <b>Заблокирован:</b> лимит трафика исчерпан",
        "card_id": "🆔 <code>{id}</code>",
        "card_created": "📅 Создан: {date}",
        "card_seen": "🕒 Последняя активность: {ago}",
        "card_up": "⬆️ Отдано: <b>{value}</b>",
        "card_down": "⬇️ Принято: <b>{value}</b>",
        "card_total": "📦 Всего: <b>{value}</b>",
        "card_pending": "📈 Ещё не учтено: +{value}",
        "card_limit": "🎯 Лимит: <b>{used}</b> из <b>{limit}</b> ({percent}%)\n{bar}",
        "card_limit_none": "🎯 Лимит: <i>не задан</i>",
        "card_link": "🔗 <b>Ссылка для подключения</b>{suffix}:",
        "card_copy_hint": "<i>Нажмите на ссылку, чтобы скопировать.</i>",
        "card_revoked_note": "<i>Ключ отозван, подключение по нему невозможно.</i>",
        # statistics
        "stats_title": "📊 <b>Статистика{suffix}</b>",
        "stats_empty": "📭 <i>Данных пока нет — создайте ключ и подключитесь.</i>",
        "stats_more": "<i>…и ещё {n} ключ(ей)</i>",
        "stats_up": "⬆️ <b>Отдано:</b> {value}",
        "stats_down": "⬇️ <b>Принято:</b> {value}",
        "stats_total": "📦 <b>Итого:</b> {value}",
        # server screen
        "server_title": "🖥 <b>Сервер</b>",
        "server_address": "📍 <b>Адрес:</b> <code>{domain}:{port}</code>",
        "server_online": "🟢 <b>Онлайн:</b> {n} устройств(а)",
        "server_online_unknown": "⚪️ <b>Онлайн:</b> <i>недоступно</i>",
        "server_keys": "🔑 <b>Ключи:</b> {active} активных · {revoked} отозванных",
        "server_traffic": "📦 <b>Трафик всего:</b> {value}",
        "server_cert_title": "📜 <b>TLS-сертификат</b>",
        "server_cert_ok": "✅ Действует до {date} (осталось {days} дн.)",
        "server_cert_soon": "⚠️ Истекает {date} — осталось {days} дн.",
        "server_cert_expired": "🔴 Истёк {date}",
        "server_cert_unknown": "⚪️ Неизвестно: <i>{error}</i>",
        "server_cert_issuer": "🏢 Выдан: {issuer}",
        "server_cert_hint": (
            "<i>Сертификат обновляет сам Hysteria2 через ACME, примерно за 30 "
            "дней до истечения. Вмешиваться не нужно.</i>"
        ),
        "cert_short_ok": "до {date} ({days} дн.)",
        "cert_short_soon": "⚠️ {days} дн. до истечения",
        "cert_short_expired": "🔴 истёк",
        "cert_short_pending": "⏳ ещё не выпущен",
        "cert_short_unknown": "не удалось прочитать",
        "server_cert_pending": (
            "⏳ Ещё не выпущен — Hysteria2 запросит его у Let's Encrypt при "
            "первом подключении."
        ),
        "server_cert_hint_refresh": (
            "<i>Данные обновляются раз в час. Чтобы проверить сейчас, "
            "выполните на сервере:</i>\n<code>hyvpn cert</code>"
        ),
        # help
        "help_title": "ℹ️ <b>Справка</b>",
        "help_commands": (
            "Всё управление — кнопками, но есть и команды:\n\n"
            "🏠 <code>/start</code> — главное меню\n"
            "➕ <code>/new Имя ключа</code> — быстро создать ключ\n"
            "🔑 <code>/keys</code> — список ключей\n"
            "📊 <code>/stats</code> — статистика трафика\n"
            "🖥 <code>/server</code> — состояние сервера и сертификата\n"
            "🌐 <code>/lang</code> — сменить язык\n"
            "🆔 <code>/id</code> — ваш Telegram ID"
        ),
        "help_connect": (
            "<b>Как подключиться</b>\n"
            "1. Установите клиент с поддержкой Hysteria2: "
            "<b>Streisand</b> или <b>V2Box</b> (iOS), "
            "<b>NekoBox</b> или <b>v2rayNG</b> (Android), "
            "<b>Hiddify</b> (Windows / macOS / Linux).\n"
            "2. Откройте карточку ключа: скопируйте ссылку или отсканируйте QR-код.\n"
            "3. Вставьте ссылку в клиент — профиль добавится сам."
        ),
        "help_note": (
            "<i>Отозванный ключ перестаёт работать сразу и не восстанавливается — "
            "вместо него выдайте новый.</i>"
        ),
        # dialogs
        "new_title": "➕ <b>Новый ключ</b>",
        "new_prompt": (
            "Как назвать ключ? Например: <code>Иван — iPhone</code>\n\n"
            "<i>Отправьте название сообщением.</i>"
        ),
        "new_created": "✅ <b>Ключ создан</b>",
        "new_label": "🏷 <b>{label}</b>{suffix}",
        "new_hint": "<i>Нажмите на ссылку, чтобы скопировать, или запросите QR-код.</i>",
        "rename_title": "✏️ <b>Переименование</b>",
        "rename_prompt": "Отправьте новое название ключа сообщением.",
        "renamed": "✏️ Переименован в <b>{label}</b>",
        "limit_title": "📦 <b>Лимит трафика</b>",
        "limit_prompt": (
            "Сколько трафика разрешить этому ключу?\n\n"
            "Примеры: <code>50 GB</code>, <code>500mb</code>, <code>1.5 TB</code>\n"
            "<code>0</code> — без лимита.\n\n"
            "<i>Отправьте значение сообщением.</i>"
        ),
        "limit_current": "Сейчас: <b>{value}</b>",
        "limit_set": "📦 Лимит установлен: <b>{value}</b>",
        "limit_cleared": "♾ Лимит снят.",
        "limit_bad": (
            "⚠️ Не понял размер. Примеры: <code>50 GB</code>, "
            "<code>500mb</code>, <code>0</code>."
        ),
        "revoke_title": "🗑 <b>Отозвать ключ?</b>",
        "revoke_warning": (
            "⚠️ <i>Подключение перестанет работать сразу. "
            "Восстановить ключ нельзя — только создать новый.</i>"
        ),
        "revoked_done": "🗑 <b>Ключ отозван</b>",
        "lang_title": "🌐 <b>Язык интерфейса</b>",
        "lang_prompt": "Выберите язык:",
        "lang_saved": "🌐 Язык переключён на русский.",
        # short answers and errors
        "empty_input": "⚠️ Значение не может быть пустым. Попробуйте ещё раз.",
        "cancelled": "❌ Отменено.",
        "toast_not_found": "Ключ не найден",
        "toast_revoked": "Ключ отозван",
        "toast_already_revoked": "Ключ уже отозван или не найден",
        "toast_qr_off": "QR-коды недоступны на сервере",
        "toast_denied": "🚫 Доступ запрещён",
        "toast_error": "⚠️ Внутренняя ошибка",
        "err_internal": (
            "⚠️ <b>Внутренняя ошибка.</b>\n"
            "Подробности — в журнале: <code>journalctl -u hy-bot -n 50</code>"
        ),
        "revoke_cmd_usage": (
            "⚠️ Укажите ID ключа: <code>/revoke &lt;id&gt;</code>\n"
            "Список ID — в <code>/keys</code>."
        ),
        "revoke_cmd_missing": "❌ Активный ключ <code>{id}</code> не найден.",
        "revoke_cmd_done": "🗑 Ключ <code>{id}</code> отозван.",
        "my_id": "🆔 Ваш Telegram ID: <code>{id}</code>",
        "unauthorized": (
            "🚫 <b>Доступ запрещён</b>\n\n"
            "Ваш Telegram ID: <code>{id}</code>\n\n"
            "<i>Если вы владелец сервера — добавьте этот ID в "
            "<code>ALLOWED_TG_IDS</code> в файле <code>/etc/hyvpn/.env.bot</code>, "
            "затем перезапустите бота:</i>\n"
            "<code>sudo systemctl restart hy-bot</code>"
        ),
        "qr_caption": "📱 <b>{label}</b>\nОтсканируйте QR-код в клиенте Hysteria2.",
    },
    "en": {
        "units": "B,KB,MB,GB,TB,PB",
        "ago_never": "never",
        "ago_now": "just now",
        "ago_min": "{n} min ago",
        "ago_hour": "{n} h ago",
        "ago_day": "{n} d ago",
        "unlimited": "unlimited",
        "btn_keys": "🔑 Keys",
        "btn_new": "➕ New key",
        "btn_new_more": "➕ One more",
        "btn_stats": "📊 Statistics",
        "btn_server": "🖥 Server",
        "btn_help": "ℹ️ Help",
        "btn_lang": "🌐 Language",
        "btn_refresh": "🔄 Refresh",
        "btn_menu": "🏠 Menu",
        "btn_back_list": "⬅️ Back to list",
        "btn_card": "🔑 Key card",
        "btn_qr": "📱 QR code",
        "btn_rename": "✏️ Rename",
        "btn_limit": "📦 Traffic limit",
        "btn_revoke": "🗑 Revoke key",
        "btn_revoke_yes": "✅ Yes, revoke",
        "btn_cancel": "❌ Cancel",
        "btn_show_revoked": "👁 Show revoked",
        "btn_only_active": "👁 Active only",
        "btn_limit_off": "♾ Remove limit",
        "menu_title": "🛡 {location}",
        "menu_keys": "🔑 <b>Keys:</b> {active} active · {revoked} revoked",
        "menu_online": "🟢 <b>Online now:</b> {n} device(s)",
        "menu_online_unknown": "⚪️ <i>Online status unavailable</i>",
        "menu_traffic": "📦 <b>Traffic:</b> ⬆️ {up} · ⬇️ {down}",
        "menu_cert": "📜 <b>Certificate:</b> {cert}",
        "menu_hint": "<i>Pick an action below.</i>",
        "keys_title_active": "🔑 <b>Keys</b> · active",
        "keys_title_all": "🔑 <b>Keys</b> · all",
        "keys_page": " · page {page}/{pages}",
        "keys_empty": (
            "📭 <i>No keys yet.</i>\n\n"
            "Tap <b>➕ New key</b> to create the first one."
        ),
        "keys_hint": "<i>Tap a key to open its card.</i>",
        "card_active": "🟢 <b>Active</b>",
        "card_online": " · 📱 {n} device(s) online",
        "card_revoked": "⚫️ <b>Revoked</b> · {date}",
        "card_blocked": "🔴 <b>Blocked:</b> traffic limit reached",
        "card_id": "🆔 <code>{id}</code>",
        "card_created": "📅 Created: {date}",
        "card_seen": "🕒 Last seen: {ago}",
        "card_up": "⬆️ Uploaded: <b>{value}</b>",
        "card_down": "⬇️ Downloaded: <b>{value}</b>",
        "card_total": "📦 Total: <b>{value}</b>",
        "card_pending": "📈 Not counted yet: +{value}",
        "card_limit": "🎯 Limit: <b>{used}</b> of <b>{limit}</b> ({percent}%)\n{bar}",
        "card_limit_none": "🎯 Limit: <i>not set</i>",
        "card_link": "🔗 <b>Connection link</b>{suffix}:",
        "card_copy_hint": "<i>Tap the link to copy it.</i>",
        "card_revoked_note": "<i>This key is revoked and can no longer connect.</i>",
        "stats_title": "📊 <b>Statistics{suffix}</b>",
        "stats_empty": "📭 <i>No data yet — create a key and connect.</i>",
        "stats_more": "<i>…and {n} more key(s)</i>",
        "stats_up": "⬆️ <b>Uploaded:</b> {value}",
        "stats_down": "⬇️ <b>Downloaded:</b> {value}",
        "stats_total": "📦 <b>Total:</b> {value}",
        "server_title": "🖥 <b>Server</b>",
        "server_address": "📍 <b>Address:</b> <code>{domain}:{port}</code>",
        "server_online": "🟢 <b>Online:</b> {n} device(s)",
        "server_online_unknown": "⚪️ <b>Online:</b> <i>unavailable</i>",
        "server_keys": "🔑 <b>Keys:</b> {active} active · {revoked} revoked",
        "server_traffic": "📦 <b>Total traffic:</b> {value}",
        "server_cert_title": "📜 <b>TLS certificate</b>",
        "server_cert_ok": "✅ Valid until {date} ({days} days left)",
        "server_cert_soon": "⚠️ Expires {date} — {days} days left",
        "server_cert_expired": "🔴 Expired on {date}",
        "server_cert_unknown": "⚪️ Unknown: <i>{error}</i>",
        "server_cert_issuer": "🏢 Issuer: {issuer}",
        "server_cert_hint": (
            "<i>Hysteria2 renews the certificate over ACME about 30 days before "
            "expiry. No action needed.</i>"
        ),
        "cert_short_ok": "until {date} ({days} d)",
        "cert_short_soon": "⚠️ {days} days left",
        "cert_short_expired": "🔴 expired",
        "cert_short_pending": "⏳ not issued yet",
        "cert_short_unknown": "could not be read",
        "server_cert_pending": (
            "⏳ Not issued yet — Hysteria2 will request it from Let's Encrypt "
            "on the first connection."
        ),
        "server_cert_hint_refresh": (
            "<i>The data refreshes hourly. To check right now, run on the "
            "server:</i>\n<code>hyvpn cert</code>"
        ),
        "help_title": "ℹ️ <b>Help</b>",
        "help_commands": (
            "Everything works with buttons, but commands exist too:\n\n"
            "🏠 <code>/start</code> — main menu\n"
            "➕ <code>/new Key name</code> — create a key quickly\n"
            "🔑 <code>/keys</code> — key list\n"
            "📊 <code>/stats</code> — traffic statistics\n"
            "🖥 <code>/server</code> — server and certificate state\n"
            "🌐 <code>/lang</code> — switch language\n"
            "🆔 <code>/id</code> — your Telegram ID"
        ),
        "help_connect": (
            "<b>How to connect</b>\n"
            "1. Install a Hysteria2-capable client: "
            "<b>Streisand</b> or <b>V2Box</b> (iOS), "
            "<b>NekoBox</b> or <b>v2rayNG</b> (Android), "
            "<b>Hiddify</b> (Windows / macOS / Linux).\n"
            "2. Open the key card: copy the link or scan the QR code.\n"
            "3. Paste the link into the client — the profile is added for you."
        ),
        "help_note": (
            "<i>A revoked key stops working immediately and cannot be restored — "
            "issue a new one instead.</i>"
        ),
        "new_title": "➕ <b>New key</b>",
        "new_prompt": (
            "What should the key be called? For example: <code>John — iPhone</code>\n\n"
            "<i>Send the name as a message.</i>"
        ),
        "new_created": "✅ <b>Key created</b>",
        "new_label": "🏷 <b>{label}</b>{suffix}",
        "new_hint": "<i>Tap the link to copy it, or ask for a QR code.</i>",
        "rename_title": "✏️ <b>Rename</b>",
        "rename_prompt": "Send the new key name as a message.",
        "renamed": "✏️ Renamed to <b>{label}</b>",
        "limit_title": "📦 <b>Traffic limit</b>",
        "limit_prompt": (
            "How much traffic is this key allowed?\n\n"
            "Examples: <code>50 GB</code>, <code>500mb</code>, <code>1.5 TB</code>\n"
            "<code>0</code> — unlimited.\n\n"
            "<i>Send the value as a message.</i>"
        ),
        "limit_current": "Currently: <b>{value}</b>",
        "limit_set": "📦 Limit set to <b>{value}</b>",
        "limit_cleared": "♾ Limit removed.",
        "limit_bad": (
            "⚠️ Could not read that size. Examples: <code>50 GB</code>, "
            "<code>500mb</code>, <code>0</code>."
        ),
        "revoke_title": "🗑 <b>Revoke this key?</b>",
        "revoke_warning": (
            "⚠️ <i>The connection stops working immediately. The key cannot be "
            "restored — you can only create a new one.</i>"
        ),
        "revoked_done": "🗑 <b>Key revoked</b>",
        "lang_title": "🌐 <b>Interface language</b>",
        "lang_prompt": "Choose a language:",
        "lang_saved": "🌐 Language switched to English.",
        "empty_input": "⚠️ The value cannot be empty. Try again.",
        "cancelled": "❌ Cancelled.",
        "toast_not_found": "Key not found",
        "toast_revoked": "Key revoked",
        "toast_already_revoked": "Key already revoked or not found",
        "toast_qr_off": "QR codes are unavailable on this server",
        "toast_denied": "🚫 Access denied",
        "toast_error": "⚠️ Internal error",
        "err_internal": (
            "⚠️ <b>Internal error.</b>\n"
            "Details are in the log: <code>journalctl -u hy-bot -n 50</code>"
        ),
        "revoke_cmd_usage": (
            "⚠️ Provide a key id: <code>/revoke &lt;id&gt;</code>\n"
            "Ids are listed in <code>/keys</code>."
        ),
        "revoke_cmd_missing": "❌ No active key <code>{id}</code>.",
        "revoke_cmd_done": "🗑 Key <code>{id}</code> revoked.",
        "my_id": "🆔 Your Telegram ID: <code>{id}</code>",
        "unauthorized": (
            "🚫 <b>Access denied</b>\n\n"
            "Your Telegram ID: <code>{id}</code>\n\n"
            "<i>If you own this server, add the ID to <code>ALLOWED_TG_IDS</code> "
            "in <code>/etc/hyvpn/.env.bot</code> and restart the bot:</i>\n"
            "<code>sudo systemctl restart hy-bot</code>"
        ),
        "qr_caption": "📱 <b>{label}</b>\nScan the QR code in a Hysteria2 client.",
    },
}

# Command descriptions shown in the Telegram command menu.
COMMAND_DESCRIPTIONS: dict[str, dict[str, str]] = {
    "ru": {
        "start": "🏠 Главное меню",
        "new": "➕ Новый ключ",
        "keys": "🔑 Список ключей",
        "stats": "📊 Статистика трафика",
        "server": "🖥 Сервер и сертификат",
        "lang": "🌐 Сменить язык",
        "help": "ℹ️ Справка",
        "id": "🆔 Мой Telegram ID",
    },
    "en": {
        "start": "🏠 Main menu",
        "new": "➕ New key",
        "keys": "🔑 Key list",
        "stats": "📊 Traffic statistics",
        "server": "🖥 Server and certificate",
        "lang": "🌐 Switch language",
        "help": "ℹ️ Help",
        "id": "🆔 My Telegram ID",
    },
}


def normalize_lang(raw: str | None) -> str:
    """Map anything to a supported language code."""
    if not raw:
        return FALLBACK_LANG
    code = str(raw).strip().lower().replace("_", "-").split("-")[0]
    return code if code in LANGS else FALLBACK_LANG


def t(lang: str, key: str, **kwargs) -> str:
    catalog = TEXTS.get(normalize_lang(lang), TEXTS[FALLBACK_LANG])
    template = catalog.get(key) or TEXTS[FALLBACK_LANG].get(key, key)
    if not kwargs:
        return template
    try:
        return template.format(**kwargs)
    except (KeyError, IndexError):  # pragma: no cover - guards typos
        return template


def units(lang: str) -> list[str]:
    return t(lang, "units").split(",")


# --------------------------------------------------------------------------- #
# size parsing
# --------------------------------------------------------------------------- #

_SIZE_RE = re.compile(
    r"^(?P<value>\d+(?:[.,]\d+)?)\s*(?P<unit>[a-zA-Zа-яА-Я]*)$",
)

_UNIT_POWERS = {
    "": 3,  # a bare number means gigabytes: "50" -> 50 GB
    "b": 0, "б": 0, "byte": 0, "bytes": 0,
    "k": 1, "kb": 1, "kib": 1, "к": 1, "кб": 1,
    "m": 2, "mb": 2, "mib": 2, "м": 2, "мб": 2,
    "g": 3, "gb": 3, "gib": 3, "г": 3, "гб": 3,
    "t": 4, "tb": 4, "tib": 4, "т": 4, "тб": 4,
    "p": 5, "pb": 5, "pib": 5, "п": 5, "пб": 5,
}

_UNLIMITED_WORDS = {
    "0", "-", "no", "none", "off", "unlimited", "infinite",
    "нет", "без", "безлимит", "выкл", "снять",
}


def parse_size(raw: str | None) -> int | None:
    """Parse a human size into bytes. 0 means unlimited, None means invalid.

    A bare number is read as gigabytes, which is what an operator typing "50"
    almost always means.
    """
    text = " ".join((raw or "").split()).lower()
    if not text:
        return None
    if text in _UNLIMITED_WORDS:
        return 0

    match = _SIZE_RE.match(text)
    if not match:
        return None

    unit = match.group("unit")
    if unit not in _UNIT_POWERS:
        return None

    try:
        value = float(match.group("value").replace(",", "."))
    except ValueError:  # pragma: no cover - regex already guarantees a number
        return None
    if value < 0:
        return None

    result = int(value * (1024 ** _UNIT_POWERS[unit]))
    return result
