import asyncio
import tempfile
from pathlib import Path

import pytest

from core.db import connect
from core.hysteria_client import TrafficDelta
from core.keys_service import (
    create_key,
    get_key,
    get_key_by_password,
    is_over_limit,
    limit_of,
    reset_traffic,
    set_traffic_limit,
    used_bytes,
)
from core.stats_service import Buffered, StatsService

GB = 1024**3


class FakeClient:
    """Stands in for the Hysteria2 Traffic Stats API."""

    def __init__(self, traffic=None, online=None):
        self.traffic = traffic or {}
        self.online = online or {}
        self.kicked: list[list[str]] = []
        self.fail_kick = False

    async def poll(self):
        return dict(self.traffic), dict(self.online)

    async def kick(self, key_ids):
        if self.fail_kick:
            raise RuntimeError("stats api down")
        self.kicked.append(list(key_ids))


def run(coro_factory):
    async def wrapper():
        with tempfile.TemporaryDirectory() as td:
            db_path = str(Path(td) / "db.sqlite3")
            await coro_factory(db_path)

    asyncio.run(wrapper())


def test_is_over_limit_accounts_for_buffered_traffic():
    async def scenario(db_path):
        db = await connect(db_path)
        try:
            created = await create_key(db, "quota", 1, "example.com", 443, 10 * GB)
            row = await get_key(db, created["id"])
            assert limit_of(row) == 10 * GB
            assert used_bytes(row) == 0
            assert not is_over_limit(row)

            # 9 GB persisted + 2 GB still in memory crosses the 10 GB quota.
            await db.execute(
                "UPDATE keys SET upload_total = ? WHERE id = ?",
                (9 * GB, created["id"]),
            )
            await db.commit()
            row = await get_key(db, created["id"])
            assert not is_over_limit(row)
            assert is_over_limit(row, 2 * GB)
        finally:
            await db.close()

    run(scenario)


def test_unlimited_keys_are_never_over_limit():
    async def scenario(db_path):
        db = await connect(db_path)
        try:
            created = await create_key(db, "free", 1, "example.com", 443)
            await db.execute(
                "UPDATE keys SET upload_total = ? WHERE id = ?",
                (500 * GB, created["id"]),
            )
            await db.commit()
            row = await get_key(db, created["id"])
            assert limit_of(row) == 0
            assert not is_over_limit(row, 100 * GB)
        finally:
            await db.close()

    run(scenario)


def test_set_and_clear_limit():
    async def scenario(db_path):
        db = await connect(db_path)
        try:
            created = await create_key(db, "k", 1, "example.com", 443)
            assert await set_traffic_limit(db, created["id"], 5 * GB)
            assert limit_of(await get_key(db, created["id"])) == 5 * GB
            assert await set_traffic_limit(db, created["id"], 0)
            assert limit_of(await get_key(db, created["id"])) == 0
            assert not await set_traffic_limit(db, "missing", 1)

            with pytest.raises(ValueError):
                await set_traffic_limit(db, created["id"], -1)
        finally:
            await db.close()

    run(scenario)


def test_reset_traffic():
    async def scenario(db_path):
        db = await connect(db_path)
        try:
            created = await create_key(db, "k", 1, "example.com", 443, GB)
            await db.execute(
                "UPDATE keys SET upload_total = ?, download_total = ? WHERE id = ?",
                (GB, GB, created["id"]),
            )
            await db.commit()
            assert await reset_traffic(db, created["id"])
            assert used_bytes(await get_key(db, created["id"])) == 0
        finally:
            await db.close()

    run(scenario)


def test_enforce_limits_kicks_only_exceeded_keys():
    async def scenario(db_path):
        db = await connect(db_path)
        try:
            over = await create_key(db, "over", 1, "example.com", 443, GB)
            under = await create_key(db, "under", 1, "example.com", 443, 100 * GB)
            free = await create_key(db, "free", 1, "example.com", 443)
            await db.execute(
                "UPDATE keys SET download_total = ? WHERE id = ?",
                (2 * GB, over["id"]),
            )
            await db.execute(
                "UPDATE keys SET download_total = ? WHERE id = ?",
                (2 * GB, free["id"]),
            )
            await db.commit()
        finally:
            await db.close()

        client = FakeClient()
        service = StatsService(db_path, client)
        kicked = await service.enforce_limits()

        # "under" is below its quota and "free" has none at all.
        assert kicked == [over["id"]]
        assert client.kicked == [[over["id"]]]
        assert under["id"] not in kicked
        assert free["id"] not in kicked

    run(scenario)


def test_enforce_limits_counts_buffered_traffic():
    async def scenario(db_path):
        db = await connect(db_path)
        try:
            created = await create_key(db, "quota", 1, "example.com", 443, GB)
            await db.execute(
                "UPDATE keys SET download_total = ? WHERE id = ?",
                (GB - 1024, created["id"]),
            )
            await db.commit()
        finally:
            await db.close()

        client = FakeClient()
        service = StatsService(db_path, client)
        assert await service.enforce_limits() == []

        # Simulate a poll that has not been flushed to SQLite yet.
        service.buffer.setdefault(created["id"], Buffered()).add(
            TrafficDelta(upload=4096, download=0)
        )
        assert service.buffered(created["id"]) == 4096
        assert await service.enforce_limits() == [created["id"]]
        assert client.kicked == [[created["id"]]]

    run(scenario)


def test_enforce_limits_survives_kick_failure():
    async def scenario(db_path):
        db = await connect(db_path)
        try:
            created = await create_key(db, "quota", 1, "example.com", 443, 1024)
            await db.execute(
                "UPDATE keys SET download_total = 4096 WHERE id = ?", (created["id"],)
            )
            await db.commit()
        finally:
            await db.close()

        client = FakeClient()
        client.fail_kick = True
        service = StatsService(db_path, client)
        # /auth still refuses the key, so a failed kick must not raise.
        assert await service.enforce_limits() == [created["id"]]

    run(scenario)


def test_auth_lookup_still_finds_a_key_over_its_limit():
    """The quota is enforced in hy-core, not by hiding the row."""

    async def scenario(db_path):
        db = await connect(db_path)
        try:
            created = await create_key(db, "quota", 1, "example.com", 443, 1024)
            await db.execute(
                "UPDATE keys SET download_total = 4096 WHERE id = ?", (created["id"],)
            )
            await db.commit()
            row = await get_key_by_password(db, created["password"])
            assert row is not None
            assert is_over_limit(row)
        finally:
            await db.close()

    run(scenario)
