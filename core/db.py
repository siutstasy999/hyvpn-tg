from __future__ import annotations

from pathlib import Path
from typing import Any

import aiosqlite

SCHEMA = """
CREATE TABLE IF NOT EXISTS keys (
    id TEXT PRIMARY KEY,
    label TEXT NOT NULL,
    password TEXT NOT NULL UNIQUE,
    owner_tg_id INTEGER,
    is_active INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    revoked_at TEXT,
    upload_total INTEGER NOT NULL DEFAULT 0,
    download_total INTEGER NOT NULL DEFAULT 0,
    last_seen_at TEXT,
    traffic_limit_bytes INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_keys_password ON keys(password);
CREATE INDEX IF NOT EXISTS idx_keys_active ON keys(is_active);

-- Per-operator bot preferences (currently the interface language).
CREATE TABLE IF NOT EXISTS bot_users (
    tg_id INTEGER PRIMARY KEY,
    lang TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
"""

# Columns added after 1.0.0. Existing databases are upgraded in place.
MIGRATIONS: tuple[tuple[str, str, str], ...] = (
    ("keys", "traffic_limit_bytes", "INTEGER NOT NULL DEFAULT 0"),
)


async def _columns(db: aiosqlite.Connection, table: str) -> set[str]:
    async with db.execute(f"PRAGMA table_info({table})") as cur:
        return {row[1] for row in await cur.fetchall()}


async def migrate(db: aiosqlite.Connection) -> list[str]:
    """Add columns introduced by later versions. Returns what was applied."""
    applied: list[str] = []
    for table, column, definition in MIGRATIONS:
        if column in await _columns(db, table):
            continue
        await db.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")
        applied.append(f"{table}.{column}")
    if applied:
        await db.commit()
    return applied


async def connect(db_path: str) -> aiosqlite.Connection:
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    db = await aiosqlite.connect(db_path, timeout=30)
    db.row_factory = aiosqlite.Row
    await db.execute("PRAGMA journal_mode=WAL;")
    await db.execute("PRAGMA synchronous=NORMAL;")
    await db.execute("PRAGMA busy_timeout=30000;")
    await db.execute("PRAGMA foreign_keys=ON;")
    await db.executescript(SCHEMA)
    await db.commit()
    await migrate(db)
    return db


async def fetchone(db: aiosqlite.Connection, sql: str, params: tuple[Any, ...] = ()):
    async with db.execute(sql, params) as cur:
        return await cur.fetchone()


async def fetchall(db: aiosqlite.Connection, sql: str, params: tuple[Any, ...] = ()):
    async with db.execute(sql, params) as cur:
        return await cur.fetchall()
