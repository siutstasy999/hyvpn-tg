"""Data access helpers used by the bot handlers."""

from __future__ import annotations

import asyncio
import io
import logging
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import aiosqlite

from core.cert_service import CertInfo, get_cert_info
from core.config import BotSettings
from core.db import connect, fetchall, fetchone
from core.hysteria_client import HysteriaStatsClient, TrafficDelta
from core.prefs import get_lang, set_lang

from .i18n import normalize_lang

log = logging.getLogger(__name__)

try:  # QR codes are a nice-to-have: the bot stays fully usable without them.
    import qrcode

    QR_AVAILABLE = True
except ImportError:  # pragma: no cover - depends on the environment
    qrcode = None
    QR_AVAILABLE = False


@asynccontextmanager
async def db_session(settings: BotSettings) -> AsyncIterator[aiosqlite.Connection]:
    db = await connect(settings.database_path)
    try:
        yield db
    finally:
        await db.close()


class LiveStats:
    """Read-only view over the Hysteria2 Traffic Stats API.

    The bot never calls ``/traffic?clear=1``: clearing is hy-core's job, and
    stealing the deltas here would corrupt the persisted totals.
    """

    def __init__(self, settings: BotSettings):
        self._enabled = bool(settings.hysteria_stats_secret)
        self._client = (
            HysteriaStatsClient(settings.stats_url, settings.hysteria_stats_secret)
            if self._enabled
            else None
        )

    @property
    def enabled(self) -> bool:
        return self._enabled

    async def online(self) -> dict[str, int]:
        if not self._client:
            return {}
        try:
            return await self._client.get_online()
        except Exception as exc:
            log.warning("online stats unavailable: %s", exc)
            return {}

    async def pending(self) -> dict[str, TrafficDelta]:
        if not self._client:
            return {}
        try:
            return await self._client.get_traffic(clear=False)
        except Exception as exc:
            log.warning("traffic stats unavailable: %s", exc)
            return {}


class CertWatcher:
    """Certificate expiry, cached so every screen refresh is not a disk read."""

    def __init__(self, settings: BotSettings, ttl_seconds: int = 300):
        self.domain = settings.server_domain
        self.acme_dir = settings.acme_dir
        self.status_path = settings.cert_status_path
        self.ttl = ttl_seconds
        self._cached: CertInfo | None = None
        self._fetched_at = 0.0
        self._lock = asyncio.Lock()

    async def get(self, force: bool = False) -> CertInfo:
        async with self._lock:
            fresh = time.monotonic() - self._fetched_at < self.ttl
            if self._cached is not None and fresh and not force:
                return self._cached
            try:
                self._cached = await asyncio.to_thread(
                    get_cert_info, self.domain, self.acme_dir, self.status_path
                )
            except Exception as exc:  # pragma: no cover - defensive
                log.warning("certificate check failed: %s", exc)
                self._cached = CertInfo(domain=self.domain, error=str(exc))
            self._fetched_at = time.monotonic()
            return self._cached


class LangStore:
    """Per-operator language with an in-memory cache."""

    def __init__(self, settings: BotSettings):
        self.default = normalize_lang(settings.default_lang)
        self.settings = settings
        self._cache: dict[int, str] = {}

    async def get(self, tg_id: int) -> str:
        if tg_id in self._cache:
            return self._cache[tg_id]
        try:
            async with db_session(self.settings) as db:
                stored = await get_lang(db, tg_id)
        except Exception as exc:  # pragma: no cover - database not ready yet
            log.warning("could not read language for %s: %s", tg_id, exc)
            stored = None
        lang = normalize_lang(stored) if stored else self.default
        self._cache[tg_id] = lang
        return lang

    async def set(self, tg_id: int, lang: str) -> str:
        lang = normalize_lang(lang)
        async with db_session(self.settings) as db:
            await set_lang(db, tg_id, lang)
        self._cache[tg_id] = lang
        return lang


async def totals(db: aiosqlite.Connection) -> dict[str, int]:
    row = await fetchone(
        db,
        """
        SELECT
            COALESCE(SUM(upload_total), 0) AS up,
            COALESCE(SUM(download_total), 0) AS down,
            COALESCE(SUM(is_active), 0) AS active,
            COUNT(*) AS total
        FROM keys
        """,
    )
    return {
        "upload": int(row["up"]),
        "download": int(row["down"]),
        "active": int(row["active"]),
        "revoked": int(row["total"]) - int(row["active"]),
    }


async def keys_page(
    db: aiosqlite.Connection,
    page: int,
    page_size: int,
    show_all: bool,
) -> tuple[list, int, int]:
    """Return (rows, normalised page, total pages) ordered newest first."""
    where = "" if show_all else "WHERE is_active = 1"
    count_row = await fetchone(db, f"SELECT COUNT(*) AS n FROM keys {where}")
    total = int(count_row["n"])
    pages = max(1, -(-total // page_size))
    page = max(1, min(page, pages))

    rows = await fetchall(
        db,
        f"""
        SELECT * FROM keys {where}
        ORDER BY is_active DESC, created_at DESC
        LIMIT ? OFFSET ?
        """,
        (page_size, (page - 1) * page_size),
    )
    return list(rows), page, pages


async def stats_rows(db: aiosqlite.Connection) -> list:
    rows = await fetchall(
        db,
        """
        SELECT id, label, upload_total, download_total, is_active,
               traffic_limit_bytes
        FROM keys
        WHERE is_active = 1
        ORDER BY (upload_total + download_total) DESC
        """,
    )
    return list(rows)


def render_qr(payload: str) -> io.BytesIO | None:
    """Render ``payload`` as a PNG QR code, or return None if unsupported."""
    if not QR_AVAILABLE:
        return None
    try:
        qr = qrcode.QRCode(
            version=None,
            error_correction=qrcode.constants.ERROR_CORRECT_M,
            box_size=8,
            border=2,
        )
        qr.add_data(payload)
        qr.make(fit=True)
        image = qr.make_image(fill_color="black", back_color="white")
        buffer = io.BytesIO()
        image.save(buffer, format="PNG")
        buffer.seek(0)
        return buffer
    except Exception as exc:  # pragma: no cover - Pillow / encoding issues
        log.warning("QR render failed: %s", exc)
        return None
