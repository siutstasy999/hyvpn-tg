"""hy-core /auth: the gate that actually blocks a connection."""

import asyncio
import os
import tempfile
from pathlib import Path

# hy_core_app reads its settings at import time.
_TMP = tempfile.TemporaryDirectory()
os.environ["DATABASE_PATH"] = str(Path(_TMP.name) / "core.sqlite3")
os.environ.setdefault("HYSTERIA_STATS_SECRET", "test-secret")
os.environ.setdefault("SERVER_DOMAIN", "vpn.example.com")

import hy_core_app  # noqa: E402
from core.db import connect  # noqa: E402
from core.hysteria_client import TrafficDelta  # noqa: E402
from core.keys_service import create_key, revoke_key, set_traffic_limit  # noqa: E402
from core.stats_service import Buffered  # noqa: E402

GB = 1024**3


def auth(password: str):
    request = hy_core_app.AuthRequest(addr="127.0.0.1:12345", auth=password, tx=0)
    return asyncio.run(hy_core_app.auth(request))


def new_key(label: str, limit: int = 0, used: int = 0) -> dict:
    async def run():
        db = await connect(os.environ["DATABASE_PATH"])
        try:
            created = await create_key(db, label, None, "vpn.example.com", 443, limit)
            if used:
                await db.execute(
                    "UPDATE keys SET download_total = ? WHERE id = ?",
                    (used, created["id"]),
                )
                await db.commit()
            return created
        finally:
            await db.close()

    return asyncio.run(run())


def teardown_module(_module):
    hy_core_app.stats_service.buffer.clear()
    _TMP.cleanup()


def test_unknown_password_is_refused():
    response = auth("not-a-real-password")
    assert response.ok is False
    assert response.id is None


def test_active_key_is_accepted():
    created = new_key("plain")
    response = auth(created["password"])
    assert response.ok is True
    assert response.id == created["id"]


def test_revoked_key_is_refused():
    created = new_key("to-revoke")

    async def revoke():
        db = await connect(os.environ["DATABASE_PATH"])
        try:
            return await revoke_key(db, created["id"])
        finally:
            await db.close()

    assert asyncio.run(revoke())
    assert auth(created["password"]).ok is False


def test_key_within_its_quota_is_accepted():
    created = new_key("under-quota", limit=10 * GB, used=1 * GB)
    assert auth(created["password"]).ok is True


def test_key_over_its_quota_is_refused():
    created = new_key("over-quota", limit=1 * GB, used=2 * GB)
    assert auth(created["password"]).ok is False


def test_quota_counts_traffic_still_buffered_in_memory():
    # 1 GB quota, 1 GB minus 4 KB persisted: still allowed.
    created = new_key("edge", limit=GB, used=GB - 4096)
    assert auth(created["password"]).ok is True

    # The last poll added 8 KB that has not been flushed yet.
    hy_core_app.stats_service.buffer.setdefault(created["id"], Buffered()).add(
        TrafficDelta(upload=8192, download=0)
    )
    assert auth(created["password"]).ok is False

    # Raising the quota lets the same key back in.
    async def raise_limit():
        db = await connect(os.environ["DATABASE_PATH"])
        try:
            return await set_traffic_limit(db, created["id"], 10 * GB)
        finally:
            await db.close()

    assert asyncio.run(raise_limit())
    assert auth(created["password"]).ok is True


def test_health_endpoint():
    assert asyncio.run(hy_core_app.health()) == {"ok": True}
