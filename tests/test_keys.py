import asyncio
import tempfile
from pathlib import Path

from core.db import connect
from core.keys_service import create_key, get_key_by_password, revoke_key


def test_key_lifecycle():
    async def run():
        with tempfile.TemporaryDirectory() as td:
            db = await connect(str(Path(td) / "db.sqlite3"))
            created = await create_key(db, "test", 123, "example.com", 443)
            assert created["id"]
            assert created["password"]
            assert created["uri"].startswith("hysteria2://")

            row = await get_key_by_password(db, created["password"])
            assert row["id"] == created["id"]

            assert await revoke_key(db, created["id"])
            assert await get_key_by_password(db, created["password"]) is None
            await db.close()

    asyncio.run(run())
