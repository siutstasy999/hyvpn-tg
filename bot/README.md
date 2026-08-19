# hy-bot — Telegram control panel

Long-polling aiogram 3 bot. Everything is driven by inline keyboards; a single
message is edited in place as the operator navigates, so the chat stays clean.
Interface languages: Russian and English.

## Files

| File | Purpose |
| --- | --- |
| `main.py` | Entry point: bot, dispatcher, middlewares, command menu, error handler |
| `handlers.py` | Commands, callbacks, three FSM inputs (create / rename / limit), routing table |
| `ui.py` | Screens and inline keyboards, all language-aware |
| `i18n.py` | Translation catalogs, command descriptions, human size parsing |
| `services.py` | SQLite access, live stats, certificate cache, language store, QR rendering |
| `middlewares.py` | `ALLOWED_TG_IDS` whitelist and language injection |

## Screens

```
🏠 Меню ──┬── 🔑 Ключи ──── 🔑 Карточка ключа ──┬── 📱 QR-код
          │      (стр. 1/N, ⚫️ отозванные)      ├── ✏️ Переименовать
          │                                     ├── 📦 Лимит трафика
          │                                     └── 🗑 Отозвать → подтверждение
          ├── ➕ Новый ключ (спросит название)
          ├── 📊 Статистика (топ по трафику + итог)
          ├── 🖥 Сервер (сертификат, онлайн, итоги)
          ├── 🌐 Язык (Русский / English)
          └── ℹ️ Справка
```

## Commands

| Command | Action |
| --- | --- |
| `/start`, `/menu` | main menu |
| `/new [label]` | create a key; without a label the bot asks for one |
| `/keys`, `/list` | key list |
| `/stats` | traffic statistics |
| `/server`, `/status` | server state and certificate expiry |
| `/lang` | switch interface language |
| `/revoke <id>`, `/delkey <id>` | revoke a key by id |
| `/help` | help screen |
| `/id` | your Telegram ID |

## Access control

`ALLOWED_TG_IDS` is the only gate, enforced for both messages and button
presses by `WhitelistMiddleware`. **An empty list denies everyone** — an open
key issuer would let any Telegram user create VPN accounts on your server.
A rejected user only learns their own Telegram ID, which is what the owner
needs to whitelist them.

## Languages

`DEFAULT_LANG` (`ru` or `en`) applies until an operator picks a language with
the 🌐 button; the choice is stored per Telegram ID in the `bot_users` table and
survives restarts. `LanguageMiddleware` injects the resolved language into every
handler as `lang`.

Adding a language means adding one catalog to `i18n.TEXTS` plus an entry in
`LANGS`, `LANG_LABELS` and `COMMAND_DESCRIPTIONS`. `tests/test_i18n.py` fails if
any catalog is missing a key or a `{placeholder}`, so translations cannot drift
apart silently.

## Traffic limits

The 📦 button accepts `50 GB`, `500mb`, `1.5 TB` or `0` to remove the quota; a
bare number is read as gigabytes (`i18n.parse_size`). Enforcement lives in
`core`: `hy-core` refuses `/auth` and kicks open sessions. The bot only shows
state — 🔴 in the list, "Заблокирован" / "Blocked" on the card.

## Live data (optional)

Set `HYSTERIA_STATS_SECRET` (and `HYSTERIA_STATS_URL`, default
`http://127.0.0.1:9999`) in `/etc/hyvpn/.env.bot` to the same value as
`TRAFFIC_STATS_SECRET` in `/etc/hyvpn/.env.hysteria`. The bot then shows how
many devices are online and how much traffic is not yet written to SQLite.

The bot reads `/traffic` **without** `clear=1`; resetting the counters remains
hy-core's job, so enabling this cannot corrupt the persisted totals. Without
the secret the bot works normally and simply hides those two numbers.

## Certificate

`CertWatcher` caches the certificate state for 5 minutes and reads it through
`core.cert_service`: the JSON snapshot from `hy-certwatch.timer` first, then the
certificate file itself, and "unknown" if neither is readable. The 🖥 Server
screen shows the expiry date, the main menu shows a short badge, and both warn
14 days ahead.

## QR codes

Provided by `qrcode[pil]` (in `requirements.txt`). If the package is missing,
the QR buttons disappear and everything else keeps working.
