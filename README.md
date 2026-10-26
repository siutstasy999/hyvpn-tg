# hyvpn-tg — Hysteria2 VPN + Telegram-бот

Свой VPN на Hysteria2 с управлением из Telegram: ключи, QR-коды, статистика
трафика, лимиты на ключ, проверка TLS-сертификата. Без Docker, без Redis, без
PostgreSQL — Python + SQLite на одном ядре и 512 МБ памяти.

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/siutstasy999/hyvpn-tg/main/install.sh)
```

Установщик задаст несколько вопросов (домен, e-mail, токен бота, ваш Telegram
ID, язык), всё настроит и покажет первый ключ вместе с QR-кодом в консоли.
Ubuntu 22.04/24.04 и Debian 11/12.

---

## Что внутри

| Компонент | Роль |
| --- | --- |
| `hysteria-server.service` | Hysteria2 на UDP/443, TLS через ACME, HTTP-auth, Traffic Stats API |
| `hy-core.service` | FastAPI: `POST /auth`, опрос `/traffic` и `/online`, лимиты, буфер в памяти, flush в SQLite |
| `hy-bot.service` | Telegram-бот (aiogram 3): ключи, QR, статистика, лимиты, сертификат |
| `hy-certwatch.timer` | Дважды в сутки записывает срок действия сертификата в JSON |
| `hyvpn` | CLI-обёртка в `/usr/local/bin` |

Общая бизнес-логика — в `core/`, её используют и бот, и CLI, и hy-core.
SQLite работает в режиме WAL. `hy-core` и `hy-bot` работают под пользователем
`hyvpn` и пишут в одну базу, поэтому `/var/lib/hyvpn` принадлежит `hyvpn:hyvpn`.

Статистика не пишется в SQLite каждую минуту: сначала накапливается в памяти,
flush — раз в 10 минут. Лимиты при этом учитывают и непролитый буфер, поэтому
ключ не может превысить квоту на целый интервал flush.

---

## Установка

### Одной командой

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/siutstasy999/hyvpn-tg/main/install.sh)
```

Перед запуском заведите домен и направьте его A-запись на IP сервера —
установщик это проверит и предупредит, если DNS ещё не обновился.

Имя профиля, которое увидят клиенты, установщик предлагает сам: он анонимно
определяет страну сервера по IP и подставляет, например, `Hysteria2 Finland 🇫🇮`.
Значение можно принять Enter'ом, переписать своим или задать флагом
`--location`. Определение делается без API-ключей и без регистрации: по очереди
опрашиваются `cloudflare.com/cdn-cgi/trace`, `api.country.is` и `ipapi.co`, и
если ни один не ответил — используется домен, как раньше.

### Без вопросов (для автоматизации)

```bash
bash install.sh --yes \
  --domain vpn.example.com \
  --email admin@example.com \
  --bot-token 123456:AA... \
  --admin-id 123456789 \
  --location "🇫🇮 Finland" \
  --lang ru
```

Всё то же можно передать переменными окружения: `HYVPN_DOMAIN`,
`HYVPN_EMAIL`, `HYVPN_BOT_TOKEN`, `HYVPN_ADMIN_IDS`, `HYVPN_LOCATION`,
`HYVPN_PORT`, `HYVPN_LANG`, `HYVPN_UFW`, `HYVPN_YES`. Полный список — в
`install.sh --help`.

### Повторный запуск = обновление

Установщик идемпотентен. При повторном запуске он:

- **не перевыпускает сертификат**, если действующий сертификат для этого домена
  ещё жив (проверяет `notAfter` через `openssl` и сообщает, сколько осталось);
- **сохраняет секрет Traffic Stats** — иначе Hysteria2 и hy-core разошлись бы
  и статистика перестала бы собираться;
- **не трогает базу ключей**;
- подставляет прежние ответы как значения по умолчанию.

Если домен меняется, установщик предупредит, что будет запрошен новый
сертификат, и спросит подтверждение.

Обновиться до последней версии из репозитория:

```bash
hyvpn update
```

---

## Управление из терминала

```bash
hyvpn status                    # сервисы, сертификат, число ключей
hyvpn key add "Иван — iPhone"   # выдать ключ
hyvpn key add "Гость" 50GB      # ключ с лимитом трафика
hyvpn key ls                    # список ключей
hyvpn key show <id>             # детали и ссылка для подключения
hyvpn key qr <id>               # QR-код в терминале
hyvpn key limit <id> 100GB      # изменить лимит (0 — снять)
hyvpn key reset <id>            # обнулить счётчики трафика
hyvpn key rm <id>               # отозвать ключ
hyvpn stats --all               # живая статистика
hyvpn cert                      # обновить и показать состояние сертификата
hyvpn logs bot 100              # журнал (core|bot|hysteria|cert)
hyvpn restart all
hyvpn backup                    # консистентная копия SQLite
hyvpn export                    # архив для переезда: база, конфиг, сертификат
hyvpn uninstall
```

Под капотом — `hy-cli.py`, его можно вызывать напрямую:

```bash
cd /opt/hyvpn
sudo -u hyvpn env PYTHONPATH=/opt/hyvpn .venv/bin/python hy-cli.py --help
```

---

## Перенос на другой сервер

Если сервер блокируют по адресу, а домен и ключи хочется сохранить — базу можно
перевезти. Пароли ключей лежат в SQLite, а в ссылке клиента нет ни IP, ни
отпечатка сертификата: только домен, порт и пароль. Поэтому после переезда
клиенты подключаются по старым ссылкам и ничего перевыпускать не нужно.

**На старом сервере** — VPN при этом продолжает работать: база снимается
онлайн (`sqlite3 .backup`), сервисы не останавливаются.

```bash
hyvpn export
```

Команда соберёт архив с базой, тремя `.env`, ACME-каталогом (сертификат
переедет) и `MANIFEST`, положит его в `/var/lib/hyvpn/backups` и напечатает
готовую команду `scp`. Выполнять её нужно на своём компьютере:

```bash
scp root@СТАРЫЙ_СЕРВЕР:/var/lib/hyvpn/backups/hyvpn-migrate-20261026-213000.tar.gz .
```

Если hyvpn на старом сервере ещё не обновлён, ту же команду можно запустить
вовсе без установки — установщик умеет только собрать архив:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/siutstasy999/hyvpn-tg/main/install.sh) --export
```

**На новом сервере** установщик сам спросит про базу:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/siutstasy999/hyvpn-tg/main/install.sh)
```

Ответ «да, забрать по SSH с прошлого сервера» → адрес → пользователь → способ
входа (ключ или пароль). Установщик сходит на старый сервер за архивом,
подставит оттуда домен, порт, имя профиля, токен бота и Telegram ID как
значения по умолчанию и применит базу до запуска сервисов. Сертификат тоже
переедет, поэтому ждать Let's Encrypt не придётся.

То же самое флагами, без вопросов:

```bash
bash install.sh --import 203.0.113.10
bash install.sh --import 203.0.113.10 --import-user root --import-password
bash install.sh --import-bundle ./hyvpn-migrate-20261026-213000.tar.gz
```

| Флаг | Что делает |
| --- | --- |
| `--import HOST` | забрать базу с другого сервера по SSH |
| `--import-user USER` | SSH-пользователь (по умолчанию `root`) |
| `--import-key PATH` | приватный ключ для этого подключения |
| `--import-password` | спросить пароль вместо ключа (ввод не отображается) |
| `--import-ssh-port N` | SSH-порт старого сервера (по умолчанию 22) |
| `--import-bundle FILE` | залить уже скачанный архив, SSH не нужен |
| `--export` / `--export-dir DIR` | собрать архив на этом сервере |

Пароль можно передать переменной `HYVPN_IMPORT_PASSWORD` — удобно для
автоматизации, но он останется в истории команд, поэтому руками лучше
`--import-password`.

Если hyvpn на новом сервере уже стоит, архив можно применить и потом:

```bash
hyvpn import ./hyvpn-migrate-20261026-213000.tar.gz
```

**Что важно знать**

- **Домен и порт менять нельзя**, иначе старые ссылки перестанут работать: они
  зашиты в ссылку. Установщик подставляет их из архива; если поменять — скажет
  об этом, и тогда клиентам нужны новые ссылки.
- **DNS.** Пока в кэше клиента старый адрес, он будет ходить в блокированный
  сервер. TTL стоит уменьшить заранее (60–300 секунд) и переключить A-запись;
  после смены клиентам обычно помогает перезапуск приложения.
- **В архиве пароли ключей и токен бота.** Не пересылайте его в мессенджерах,
  скачивайте по `scp` и удаляйте после переноса.
- **Нет SSH до старого сервера?** Тогда `--export` на нём (например, через
  консоль провайдера), скачать архив `scp`, на новом — `--import-bundle`.
- Счётчики трафика и лимиты переезжают вместе с базой, так что квоты клиентов
  не обнуляются.

---

## Telegram-бот

Всё управление — инлайн-кнопками; бот редактирует одно сообщение, поэтому чат
не засоряется. Интерфейс на русском и английском, язык переключается кнопкой
🌐 и запоминается для каждого администратора.

```
🏠 Меню ──┬── 🔑 Ключи ──── 🔑 Карточка ключа ──┬── 📱 QR-код
          │      (стр. 1/N, ⚫️ отозванные)      ├── ✏️ Переименовать
          │                                     ├── 📦 Лимит трафика
          │                                     └── 🗑 Отозвать → подтверждение
          ├── ➕ Новый ключ (спросит название)
          ├── 📊 Статистика (топ по трафику + итог)
          ├── 🖥 Сервер (сертификат, онлайн, итоги)
          ├── 🌐 Язык (Русский / English)
          └── ℹ️ Справка (какие клиенты, как подключиться)
```

Команды тоже работают: `/start`, `/new [название]`, `/keys`, `/stats`,
`/server`, `/lang`, `/revoke <id>`, `/help`, `/id`.

Доступ определяется только `ALLOWED_TG_IDS` и проверяется и для сообщений, и
для нажатий на кнопки. **Пустой список запрещает доступ всем.** Незнакомец в
ответ узнаёт лишь свой Telegram ID — его и нужно добавить в whitelist.

Подробнее — [bot/README.md](bot/README.md).

---

## Лимиты трафика

Лимит задаётся на ключ: кнопкой 📦 в боте (`50 GB`, `500mb`, `1.5 TB`, `0` —
снять) или через `hyvpn key limit <id> 50GB`. Голое число понимается как
гигабайты.

Когда квота исчерпана:

1. `hy-core` отказывает в `POST /auth` — новое подключение не установится;
2. при следующем опросе (по умолчанию раз в 60 с) `hy-core` вызывает
   `POST /kick` у Traffic Stats API и обрывает уже открытые сессии;
3. ключ в списке помечается 🔴, в карточке — «Заблокирован».

Счётчики обнуляются командой `hyvpn key reset <id>` — например, в начале
нового месяца. Сам лимит при этом остаётся.

---

## Сертификат

Сертификат получает и продлевает сам Hysteria2 через ACME, примерно за 30 дней
до истечения — вмешиваться не нужно. Состояние видно в боте (🖥 Сервер) и в
`hyvpn cert`.

ACME-каталог принадлежит пользователю `hysteria`, а бот работает под `hyvpn` и
не должен иметь к нему доступа. Поэтому `hy-certwatch.timer` **раз в час**
запускает `bin/cert_probe.py` от root и складывает срок действия в
`/var/lib/hyvpn/cert.json` — бот читает только этот файл. Установщик к тому же
ждёт выпуск сертификата до 60 секунд, поэтому реальное состояние видно сразу
после установки.

Бот различает три состояния:

| В боте | Что значит |
| --- | --- |
| ✅ дата и сколько дней осталось | всё в порядке |
| ⏳ ещё не выпущен | нормально для нового сервера: Hysteria2 запросит сертификат при первом подключении |
| ⚪️ не удалось прочитать | вот это уже проблема — смотрите `hyvpn logs hysteria` |

Проверить состояние прямо сейчас, не дожидаясь часового таймера:

```bash
hyvpn cert
```

---

## Конфигурация

Установщик генерирует три файла с правами `0640 root:hyvpn`:

| Файл | Для кого |
| --- | --- |
| `/etc/hyvpn/.env.core` | hy-core, CLI, certwatch |
| `/etc/hyvpn/.env.bot` | hy-bot |
| `/etc/hyvpn/.env.hysteria` | шаблон конфига Hysteria2 |

Ключевые переменные:

```dotenv
# .env.core
DATABASE_PATH=/var/lib/hyvpn/hyvpn.sqlite3
HYSTERIA_STATS_URL=http://127.0.0.1:9999
HYSTERIA_STATS_SECRET=...      # тот же, что TRAFFIC_STATS_SECRET
POLL_INTERVAL_SECONDS=60
FLUSH_INTERVAL_SECONDS=600
SERVER_DOMAIN=vpn.example.com
SERVER_PORT=443
LOCATION_NAME=Hysteria2 Finland 🇫🇮   # имя профиля в клиентах
ACME_DIR=/var/lib/hysteria/acme
CERT_STATUS_PATH=/var/lib/hyvpn/cert.json

# .env.bot
BOT_TOKEN=123456:...
ALLOWED_TG_IDS=123456789,987654321
DEFAULT_LANG=ru                # язык до первого выбора кнопкой
HYSTERIA_STATS_SECRET=...      # необязательно: включает «онлайн сейчас»

# .env.hysteria
TRAFFIC_STATS_SECRET=...
ACME_DOMAIN=vpn.example.com
ACME_EMAIL=admin@example.com
```

`hysteria-server.yaml` — шаблон: systemd рендерит его в
`/run/hyvpn/hysteria-server.yaml` с правами 0600, чтобы секрет не лежал в git.

После правки любого файла:

```bash
hyvpn restart all
```

---

## Ссылка для подключения

```text
hysteria2://<password>@vpn.example.com:443/?sni=vpn.example.com#🇫🇮 Finland
```

Имя профиля во фрагменте — это `LOCATION_NAME` (или домен), в человеческом
виде, без `%D0%9F%25...`. Метка ключа в ссылку **не** попадает: один сервер
должен выглядеть одинаково во всех клиентах, а кому выдан ключ — видно в боте.

Если вы планируете пересылать ссылки текстом в мессенджерах, лучше выбрать
имя без пробелов (`Finland` вместо `Hysteria2 Finland`) — иначе некоторые
клиенты обрежут ссылку по первому пробелу.

Клиенты: **Streisand** / **V2Box** (iOS), **NekoBox** / **v2rayNG** (Android),
**Hiddify** (Windows / macOS / Linux).

---

## Брандмауэр

Установщик (если разрешить) открывает только необходимое:

```bash
sudo ufw allow 22/tcp      # SSH
sudo ufw allow 443/udp     # Hysteria2
sudo ufw allow 80/tcp      # ACME HTTP-01
```

`8080/tcp` (hy-core) и `9999/tcp` (Traffic Stats) слушают только `127.0.0.1` и
наружу не открываются никогда.

---

## Разработка

```bash
python -m venv .venv
.venv/bin/pip install -r requirements.txt pytest
BOT_TOKEN=1:test ALLOWED_TG_IDS=1 SERVER_DOMAIN=example.com .venv/bin/pytest -q
```

Тесты гоняют настоящий dispatcher aiogram через фейковый транспорт Telegram,
так что сценарии бота проверяются без обращения к Telegram API. CI дополнительно
запускает `install.sh --dry-run` в контейнерах Ubuntu 22.04/24.04 и Debian 12.

Проверить установщик локально, ничего не запуская в systemd:

```bash
sudo bash install.sh --dry-run --domain vpn.example.com \
  --email a@b.co --bot-token 123456789:AA... --admin-id 1 --no-ufw
```

---

## Диагностика

| Симптом | Что смотреть |
| --- | --- |
| Бот молчит | `hyvpn logs bot` — скорее всего, ваш ID не в `ALLOWED_TG_IDS` |
| Бот отвечает «Доступ запрещён» | добавьте показанный ID в `ALLOWED_TG_IDS`, затем `hyvpn restart bot` |
| Не подключается | `hyvpn logs hysteria` — обычно ACME не смог выпустить сертификат (DNS или закрытый TCP/80) |
| «Статус онлайн недоступен» | в `.env.bot` не задан `HYSTERIA_STATS_SECRET` |
| Ключ не работает после лимита | так и задумано: `hyvpn key limit <id> 0` или `hyvpn key reset <id>` |
| Сертификат «неизвестно» | `hyvpn cert`; проверьте `systemctl status hy-certwatch.timer` |

```bash
journalctl -u hy-core -u hy-bot -u hysteria-server -n 100 --no-pager
```

---

## Безопасность

- Секреты только в `/etc/hyvpn/.env.*` (`0640 root:hyvpn`), в git — лишь
  `*.example`.
- `hy-core` и `hy-bot` работают без root, с systemd-hardening
  (`ProtectSystem=strict`, `NoNewPrivileges`, `ReadWritePaths=/var/lib/hyvpn`).
- Hysteria2 работает под `hysteria` и получает только
  `CAP_NET_BIND_SERVICE` + `CAP_NET_ADMIN`.
- Пароли ключей — `secrets.token_urlsafe(32)`.
- Отзыв ключа необратим: `is_active=0`, `/auth` перестаёт его пускать сразу.

---

## Благодарности и лицензии

Этот проект — **обвязка**, а не VPN-протокол. Всю работу по передаче трафика
делает [Hysteria 2](https://github.com/apernet/hysteria) — отдельный проект
под лицензией MIT, автор [@apernet](https://github.com/apernet).
Документация: [v2.hysteria.network](https://v2.hysteria.network/).

`hyvpn-tg` не входит в проект Hysteria, никак с ним не связан и не является
официальным. Он лишь устанавливает Hysteria2 официальным установщиком
(`get.hy2.sh`), пишет для него конфиг и добавляет сверху: выдачу ключей,
HTTP-авторизацию, учёт трафика, лимиты и Telegram-бота.

Двоичный файл Hysteria2 в этом репозитории не распространяется — он
скачивается на сервер при установке, поэтому здесь лежит только собственный
код. Если вы форкаете проект и начинаете распространять сам бинарник Hysteria,
приложите к нему [текст лицензии MIT из репозитория Hysteria](https://github.com/apernet/hysteria/blob/master/LICENSE).

Также используются:

| Библиотека | Лицензия | Для чего |
| --- | --- | --- |
| [aiogram](https://github.com/aiogram/aiogram) | MIT | Telegram-бот |
| [FastAPI](https://github.com/fastapi/fastapi) | MIT | HTTP-авторизация Hysteria2 |
| [uvicorn](https://github.com/encode/uvicorn) | BSD-3-Clause | ASGI-сервер |
| [aiosqlite](https://github.com/omnilib/aiosqlite) | MIT | асинхронный SQLite |
| [pydantic](https://github.com/pydantic/pydantic) / [pydantic-settings](https://github.com/pydantic/pydantic-settings) | MIT | конфигурация |
| [python-qrcode](https://github.com/lincolnloop/python-qrcode) | BSD-3-Clause | QR-коды |
| [Pillow](https://github.com/python-pillow/Pillow) | MIT-CMU | отрисовка QR в PNG |

Сертификаты выпускает [Let's Encrypt](https://letsencrypt.org/) через ACME —
пользуясь установщиком, вы соглашаетесь с их
[Subscriber Agreement](https://letsencrypt.org/repository/).

## Лицензия

[MIT](LICENSE) — используйте, изменяйте и распространяйте свободно, в том числе
в коммерческих целях; единственное условие — сохранить текст лицензии и
уведомление об авторстве. Программа поставляется «как есть», без гарантий.

Вы отвечаете за то, как используете сервер, и за соблюдение законов своей
юрисдикции и правил своего хостинг-провайдера.
