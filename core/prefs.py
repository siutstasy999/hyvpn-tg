"""Per-operator bot preferences stored in SQLite."""

from __future__ import annotations

from datetime import datetime, timezone

import aiosqlite

from .db import fetchone


async def get_lang(db: aiosqlite.Connection, tg_id: int) -> str | None:
    row = await fetchone(db, "SELECT lang FROM bot_users WHERE tg_id = ?", (tg_id,))
    return row["lang"] if row else None


async def set_lang(db: aiosqlite.Connection, tg_id: int, lang: str) -> None:
    await db.execute(
        """
        INSERT INTO bot_users (tg_id, lang, updated_at)
        VALUES (?, ?, ?)
        ON CONFLICT(tg_id) DO UPDATE SET lang = excluded.lang,
                                         updated_at = excluded.updated_at
        """,
        (tg_id, lang, datetime.now(timezone.utc).isoformat()),
    )
    await db.commit()
