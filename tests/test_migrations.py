"""Upgrading a 1.0.0 database must not lose keys."""

import asyncio
import sqlite3
import tempfile
from pathlib import Path

from core.db import connect, migrate
from core.keys_service import get_key, limit_of, set_traffic_limit

OLD_SCHEMA = """
CREATE TABLE keys (
    id TEXT PRIMARY KEY,
    label TEXT NOT NULL,
    password TEXT NOT NULL UNIQUE,
    owner_tg_id INTEGER,
    is_active INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    revoked_at TEXT,
    upload_total INTEGER NOT NULL DEFAULT 0,
    download_total INTEGER NOT NULL DEFAULT 0,
    last_seen_at TEXT
);
"""


def make_old_database(path: Path) -> None:
    legacy = sqlite3.connect(path)
    legacy.executescript(OLD_SCHEMA)
    legacy.execute(
        "INSERT INTO keys (id, label, password, is_active, created_at, upload_total)"
        " VALUES ('old-id', 'legacy key', 'secret', 1, '2026-01-01T00:00:00+00:00', 42)"
    )
    legacy.commit()
    legacy.close()


def test_old_database_gains_the_limit_column():
    async def run():
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "db.sqlite3"
            make_old_database(path)

            db = await connect(str(path))
            try:
                row = await get_key(db, "old-id")
                assert row is not None
                assert row["label"] == "legacy key"
                assert row["upload_total"] == 42
                # New column exists and defaults to "no quota".
                assert limit_of(row) == 0

                assert await set_traffic_limit(db, "old-id", 1024)
                assert limit_of(await get_key(db, "old-id")) == 1024

                # bot_users is created by the same upgrade.
                await db.execute(
                    "INSERT INTO bot_users (tg_id, lang, updated_at)"
                    " VALUES (1, 'en', '2026-01-01T00:00:00+00:00')"
                )
                await db.commit()

                # Migrating again is a no-op.
                assert await migrate(db) == []
            finally:
                await db.close()

    asyncio.run(run())


def test_fresh_database_needs_no_migration():
    async def run():
        with tempfile.TemporaryDirectory() as td:
            db = await connect(str(Path(td) / "db.sqlite3"))
            try:
                assert await migrate(db) == []
            finally:
                await db.close()

    asyncio.run(run())
