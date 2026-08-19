from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass

from .db import connect
from .hysteria_client import HysteriaStatsClient, TrafficDelta
from .keys_service import (
    add_totals,
    get_key,
    is_over_limit,
    list_limited_keys,
    mark_seen,
)

log = logging.getLogger(__name__)


@dataclass
class Buffered:
    upload: int = 0
    download: int = 0

    def add(self, delta: TrafficDelta) -> None:
        self.upload += delta.upload
        self.download += delta.download


class StatsService:
    def __init__(
        self,
        db_path: str,
        client: HysteriaStatsClient,
        poll_interval: int = 60,
        flush_interval: int = 600,
    ):
        self.db_path = db_path
        self.client = client
        self.poll_interval = poll_interval
        self.flush_interval = flush_interval
        self.buffer: dict[str, Buffered] = {}
        self._poll_lock = asyncio.Lock()
        self._flush_lock = asyncio.Lock()
        self._stop = asyncio.Event()
        self._poll_task: asyncio.Task | None = None
        self._flush_task: asyncio.Task | None = None

    async def start(self) -> None:
        self._stop.clear()
        try:
            await self._poll_once()
        except Exception:
            # Hysteria may not be up yet. Keep hy-core alive so Hysteria can
            # start after its auth backend is already listening.
            pass
        self._poll_task = asyncio.create_task(self._poll_loop(), name="hy-poll")
        self._flush_task = asyncio.create_task(self._flush_loop(), name="hy-flush")

    async def stop(self) -> None:
        self._stop.set()
        tasks = [task for task in (self._poll_task, self._flush_task) if task]
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        await self.flush_all()

    async def _poll_loop(self) -> None:
        while not self._stop.is_set():
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=self.poll_interval)
            except TimeoutError:
                try:
                    await self._poll_once()
                except Exception:
                    # The next cycle retries. Do not kill hy-core because Hysteria
                    # was temporarily restarted.
                    continue

    async def _flush_loop(self) -> None:
        while not self._stop.is_set():
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=self.flush_interval)
            except TimeoutError:
                try:
                    await self.flush_all()
                except Exception:
                    continue

    async def _poll_once(self) -> dict[str, TrafficDelta]:
        async with self._poll_lock:
            traffic, online = await self.client.poll()

            for key_id, delta in traffic.items():
                self.buffer.setdefault(key_id, Buffered()).add(delta)

            if online:
                db = await connect(self.db_path)
                try:
                    await db.execute("BEGIN")
                    for key_id, count in online.items():
                        if count > 0:
                            await mark_seen(db, key_id)
                    await db.commit()
                finally:
                    await db.close()

        # Outside the poll lock: enforce_limits() only reads SQLite and calls
        # /kick, so it must not block the next polling cycle.
        try:
            await self.enforce_limits()
        except Exception as exc:
            log.warning("limit enforcement failed: %s", exc)

        return traffic

    def buffered(self, key_id: str) -> int:
        """Bytes counted in memory but not yet written to SQLite."""
        value = self.buffer.get(key_id)
        return (value.upload + value.download) if value else 0

    async def enforce_limits(self) -> list[str]:
        """Kick active keys that reached their traffic quota.

        /auth blocks the next handshake, but an established session keeps
        running until Hysteria is told to drop it.
        """
        db = await connect(self.db_path)
        try:
            rows = await list_limited_keys(db)
        finally:
            await db.close()

        exceeded = [
            str(row["id"])
            for row in rows
            if is_over_limit(row, self.buffered(str(row["id"])))
        ]
        if not exceeded:
            return []

        try:
            await self.client.kick(exceeded)
            log.info("kicked %s key(s) over their traffic limit", len(exceeded))
        except Exception as exc:
            # Not fatal: /auth still refuses the next connection attempt.
            log.warning("could not kick keys over limit: %s", exc)
        return exceeded

    async def flush_all(self) -> None:
        async with self._flush_lock:
            if not self.buffer:
                return

            snapshot = self.buffer
            self.buffer = {}

            db = await connect(self.db_path)
            try:
                await db.execute("BEGIN")
                for key_id, value in snapshot.items():
                    await add_totals(db, key_id, value.upload, value.download)
                await db.commit()
            except Exception:
                await db.rollback()
                # Reinsert the snapshot so a transient SQLite error doesn't lose
                # traffic deltas.
                for key_id, value in snapshot.items():
                    current = self.buffer.setdefault(key_id, Buffered())
                    current.upload += value.upload
                    current.download += value.download
                raise
            finally:
                await db.close()

    async def get_live_stats(self, key_id: str) -> dict:
        # Serialize with polling so clear=1 cannot race with another poll.
        async with self._poll_lock:
            traffic, online = await self.client.poll()

            for current_id, delta in traffic.items():
                self.buffer.setdefault(current_id, Buffered()).add(delta)

            current = self.buffer.pop(key_id, Buffered())

            db = await connect(self.db_path)
            try:
                row = await get_key(db, key_id)
                if row is None:
                    raise KeyError(key_id)

                await db.execute("BEGIN")
                await add_totals(db, key_id, current.upload, current.download)
                if online.get(key_id, 0) > 0:
                    await mark_seen(db, key_id)
                await db.commit()

                # Read the post-flush persistent totals.
                row = await get_key(db, key_id)
                return {
                    "id": row["id"],
                    "label": row["label"],
                    "is_active": bool(row["is_active"]),
                    "upload_total": int(row["upload_total"]),
                    "download_total": int(row["download_total"]),
                    "last_seen_at": row["last_seen_at"],
                    "traffic_limit_bytes": int(row["traffic_limit_bytes"] or 0),
                    "online": int(online.get(key_id, 0)),
                }
            except Exception:
                await db.rollback()
                current_buffer = self.buffer.setdefault(key_id, Buffered())
                current_buffer.upload += current.upload
                current_buffer.download += current.download
                raise
            finally:
                await db.close()
