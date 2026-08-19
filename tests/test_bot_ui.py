import asyncio
import os
import tempfile
from pathlib import Path

os.environ.setdefault("BOT_TOKEN", "123456:test")
os.environ.setdefault("ALLOWED_TG_IDS", "1")
os.environ.setdefault("SERVER_DOMAIN", "vpn.example.com")

from bot import services, ui  # noqa: E402
from core.db import connect  # noqa: E402
from core.keys_service import (  # noqa: E402
    create_key,
    get_key,
    rename_key,
    revoke_key,
    set_traffic_limit,
)


def test_fmt_bytes():
    assert ui.fmt_bytes("ru", None) == "0 Б"
    assert ui.fmt_bytes("en", 0) == "0 B"
    assert ui.fmt_bytes("en", 1536) == "1.50 KB"
    assert ui.fmt_bytes("ru", 1536) == "1.50 КБ"
    assert ui.fmt_bytes("en", 15 * 1024**3) == "15.00 GB"
    assert ui.fmt_bytes("en", 5 * 1024**6).endswith("PB")


def test_labels_are_html_escaped():
    assert ui.esc("<b>x</b> & y") == "&lt;b&gt;x&lt;/b&gt; &amp; y"


def test_progress_bar():
    assert ui.progress_bar(0, 0) == "░" * 10
    assert ui.progress_bar(10, 10) == "█" * 10
    assert len(ui.progress_bar(3, 10)) == 10


def test_screens_render_in_both_languages():
    async def run():
        with tempfile.TemporaryDirectory() as td:
            db = await connect(str(Path(td) / "db.sqlite3"))
            try:
                await scenario(db)
            finally:
                await db.close()

    asyncio.run(run())


async def scenario(db):
    created = []
    for index in range(8):
        created.append(
            await create_key(db, f"key <{index}>", 1, "vpn.example.com", 443)
        )
    assert await rename_key(db, created[0]["id"], "renamed & ok")
    assert await revoke_key(db, created[1]["id"])
    assert await set_traffic_limit(db, created[2]["id"], 50 * 1024**3)

    summary = await services.totals(db)
    assert summary["active"] == 7
    assert summary["revoked"] == 1

    rows, page, pages = await services.keys_page(db, 1, ui.PAGE_SIZE, False)
    assert len(rows) == ui.PAGE_SIZE
    assert (page, pages) == (1, 2)

    # Out-of-range pages clamp instead of showing an empty screen.
    _, page, pages = await services.keys_page(db, 99, ui.PAGE_SIZE, False)
    assert page == pages == 2

    _, _, all_pages = await services.keys_page(db, 1, ui.PAGE_SIZE, True)
    assert all_pages == 2

    for lang in ("ru", "en"):
        # The renamed (oldest) key is on the last page.
        last_rows, _, _ = await services.keys_page(db, 2, ui.PAGE_SIZE, False)
        assert "renamed &amp; ok" in ui.screen_keys(lang, last_rows, 2, 2, False)
        assert ui.kb_keys(lang, rows, 1, 2, False).inline_keyboard

        row = await get_key(db, created[0]["id"])
        card = ui.screen_key(
            lang,
            row,
            uri="hysteria2://x@vpn.example.com:443/?sni=vpn.example.com#Finland",
            location="Finland",
            online=2,
            pending_upload=1024,
            pending_download=2048,
        )
        assert "renamed &amp; ok" in card
        assert "3.00 " in card  # traffic not yet flushed

        limited = await get_key(db, created[2]["id"])
        assert "50.00 " in ui.screen_key(lang, limited, uri="x", location="", online=0)

        revoked_row = await get_key(db, created[1]["id"])
        assert ui.screen_key(lang, revoked_row, uri="", location="", online=None)

        stats = await services.stats_rows(db)
        assert ui.screen_stats(lang, stats, "Finland", {})
        assert ui.screen_stats(lang, [], "", {})

        assert ui.screen_menu(
            lang,
            location="Finland",
            domain="vpn.example.com",
            port=443,
            active=7,
            revoked=1,
            online=None,
            upload=0,
            download=0,
            cert=None,
        )
        assert ui.screen_server(
            lang,
            domain="vpn.example.com",
            port=443,
            active=7,
            revoked=1,
            online=3,
            traffic=0,
            cert=None,
        )
        assert ui.screen_help(lang)
        assert ui.screen_lang(lang)
        assert ui.screen_limit_prompt(lang, limited)
        assert ui.screen_revoke_confirm(lang, row)
        assert "42" in ui.screen_unauthorized(lang, 42)


def test_key_over_limit_is_marked_blocked():
    async def run():
        with tempfile.TemporaryDirectory() as td:
            db = await connect(str(Path(td) / "db.sqlite3"))
            try:
                created = await create_key(db, "quota", 1, "vpn.example.com", 443)
                await set_traffic_limit(db, created["id"], 1024)
                await db.execute(
                    "UPDATE keys SET upload_total = 2048 WHERE id = ?",
                    (created["id"],),
                )
                await db.commit()
                row = await get_key(db, created["id"])
                assert "Заблокирован" in ui.screen_key(
                    "ru", row, uri="x", location="", online=0
                )
                assert "Blocked" in ui.screen_key(
                    "en", row, uri="x", location="", online=0
                )
                assert "🔴" in ui.screen_keys("ru", [row], 1, 1, False)
            finally:
                await db.close()

    asyncio.run(run())


def test_live_stats_disabled_without_secret():
    class FakeSettings:
        hysteria_stats_secret = ""
        stats_url = "http://127.0.0.1:9999"

    live = services.LiveStats(FakeSettings())
    assert live.enabled is False
    assert asyncio.run(live.online()) == {}
    assert asyncio.run(live.pending()) == {}


def test_live_stats_survives_unreachable_api():
    class FakeSettings:
        hysteria_stats_secret = "secret"
        # Port 1 is closed, so every request fails.
        stats_url = "http://127.0.0.1:1"

    live = services.LiveStats(FakeSettings())
    assert live.enabled is True
    assert asyncio.run(live.online()) == {}
    assert asyncio.run(live.pending()) == {}
