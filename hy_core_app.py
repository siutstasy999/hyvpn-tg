from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from pydantic import BaseModel

from core.config import get_settings
from core.db import connect
from core.hysteria_client import HysteriaStatsClient
from core.keys_service import get_key_by_password, is_over_limit, limit_of, used_bytes
from core.stats_service import StatsService

log = logging.getLogger("hy-core")


settings = get_settings()
stats_client = HysteriaStatsClient(
    settings.stats_url,
    settings.hysteria_stats_secret,
)
stats_service = StatsService(
    db_path=settings.database_path,
    client=stats_client,
    poll_interval=settings.poll_interval_seconds,
    flush_interval=settings.flush_interval_seconds,
)


class AuthRequest(BaseModel):
    addr: str
    auth: str
    tx: int


class AuthResponse(BaseModel):
    ok: bool
    id: str | None = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    db = await connect(settings.database_path)
    await db.close()
    await stats_service.start()
    try:
        yield
    finally:
        await stats_service.stop()


app = FastAPI(
    title="hy-core",
    docs_url=None,
    redoc_url=None,
    lifespan=lifespan,
)


@app.post("/auth", response_model=AuthResponse)
async def auth(request: AuthRequest):
    db = await connect(settings.database_path)
    try:
        row = await get_key_by_password(db, request.auth)
    finally:
        await db.close()

    if row is None:
        return AuthResponse(ok=False)

    key_id = str(row["id"])
    # Traffic buffered in memory counts too, otherwise a key could overshoot
    # its quota by a whole flush interval.
    if is_over_limit(row, stats_service.buffered(key_id)):
        log.info(
            "auth refused for %s: traffic limit reached (%s/%s bytes)",
            key_id,
            used_bytes(row) + stats_service.buffered(key_id),
            limit_of(row),
        )
        return AuthResponse(ok=False)

    return AuthResponse(ok=True, id=key_id)


@app.get("/health")
async def health():
    return {"ok": True}


async def live_stats(key_id: str) -> dict:
    return await stats_service.get_live_stats(key_id)
