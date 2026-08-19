from __future__ import annotations

import secrets
import uuid
from datetime import datetime, timezone

import aiosqlite

from .db import fetchall, fetchone
from .uri import build_uri

MAX_LABEL = 200


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def generate_password() -> str:
    # URL-safe and sufficiently random for a Hysteria2 auth secret.
    return secrets.token_urlsafe(32)


def _validate_label(label: str) -> str:
    label = " ".join((label or "").split())
    if not label:
        raise ValueError("label must not be empty")
    if len(label) > MAX_LABEL:
        raise ValueError("label is too long")
    return label


def _validate_limit(limit: int | None) -> int:
    limit = int(limit or 0)
    if limit < 0:
        raise ValueError("traffic limit must not be negative")
    return limit


async def create_key(
    db: aiosqlite.Connection,
    label: str,
    owner_tg_id: int | None = None,
    server_domain: str | None = None,
    server_port: int = 443,
    traffic_limit_bytes: int = 0,
    profile_name: str = "",
) -> dict:
    """Create an active key. ``traffic_limit_bytes`` of 0 means unlimited."""
    label = _validate_label(label)
    traffic_limit_bytes = _validate_limit(traffic_limit_bytes)

    key_id = str(uuid.uuid4())
    password = generate_password()
    created_at = utcnow()

    await db.execute(
        """
        INSERT INTO keys
        (id, label, password, owner_tg_id, is_active, created_at, traffic_limit_bytes)
        VALUES (?, ?, ?, ?, 1, ?, ?)
        """,
        (key_id, label, password, owner_tg_id, created_at, traffic_limit_bytes),
    )
    await db.commit()

    uri = None
    if server_domain:
        uri = build_uri(
            password,
            server_domain,
            server_port,
            profile_name or server_domain,
        )

    return {
        "id": key_id,
        "label": label,
        "password": password,
        "owner_tg_id": owner_tg_id,
        "created_at": created_at,
        "traffic_limit_bytes": traffic_limit_bytes,
        "uri": uri,
    }


async def rename_key(db: aiosqlite.Connection, key_id: str, label: str) -> bool:
    label = _validate_label(label)
    result = await db.execute(
        "UPDATE keys SET label = ? WHERE id = ?",
        (label, key_id),
    )
    await db.commit()
    return result.rowcount == 1


async def set_traffic_limit(
    db: aiosqlite.Connection, key_id: str, limit_bytes: int
) -> bool:
    """Set (or clear, with 0) the traffic quota of a key."""
    limit_bytes = _validate_limit(limit_bytes)
    result = await db.execute(
        "UPDATE keys SET traffic_limit_bytes = ? WHERE id = ?",
        (limit_bytes, key_id),
    )
    await db.commit()
    return result.rowcount == 1


async def reset_traffic(db: aiosqlite.Connection, key_id: str) -> bool:
    """Zero the counters, e.g. at the start of a new billing period."""
    result = await db.execute(
        "UPDATE keys SET upload_total = 0, download_total = 0 WHERE id = ?",
        (key_id,),
    )
    await db.commit()
    return result.rowcount == 1


async def get_key_by_password(db: aiosqlite.Connection, password: str):
    return await fetchone(
        db,
        """
        SELECT *
        FROM keys
        WHERE password = ? AND is_active = 1
        LIMIT 1
        """,
        (password,),
    )


async def get_key(db: aiosqlite.Connection, key_id: str):
    return await fetchone(db, "SELECT * FROM keys WHERE id = ?", (key_id,))


async def list_keys(db: aiosqlite.Connection, active_only: bool = False):
    sql = "SELECT * FROM keys"
    if active_only:
        sql += " WHERE is_active = 1"
    sql += " ORDER BY created_at DESC"
    return await fetchall(db, sql)


async def list_limited_keys(db: aiosqlite.Connection):
    """Active keys that have a quota, for limit enforcement."""
    return await fetchall(
        db,
        """
        SELECT id, upload_total, download_total, traffic_limit_bytes
        FROM keys
        WHERE is_active = 1 AND traffic_limit_bytes > 0
        """,
    )


def used_bytes(row) -> int:
    return int(row["upload_total"] or 0) + int(row["download_total"] or 0)


def limit_of(row) -> int:
    try:
        return int(row["traffic_limit_bytes"] or 0)
    except (KeyError, IndexError):  # pragma: no cover - pre-migration rows
        return 0


def is_over_limit(row, extra_bytes: int = 0) -> bool:
    """True when the key has a quota and has reached it.

    ``extra_bytes`` covers traffic that is buffered in memory and not yet
    written to SQLite, so a key cannot overshoot its quota by a whole flush
    interval.
    """
    limit = limit_of(row)
    if limit <= 0:
        return False
    return used_bytes(row) + max(0, extra_bytes) >= limit


async def revoke_key(db: aiosqlite.Connection, key_id: str) -> bool:
    result = await db.execute(
        """
        UPDATE keys
        SET is_active = 0, revoked_at = ?
        WHERE id = ? AND is_active = 1
        """,
        (utcnow(), key_id),
    )
    await db.commit()
    return result.rowcount == 1


async def add_totals(
    db: aiosqlite.Connection,
    key_id: str,
    upload: int,
    download: int,
) -> None:
    if upload < 0 or download < 0:
        raise ValueError("traffic delta must be non-negative")
    if upload == 0 and download == 0:
        return

    await db.execute(
        """
        UPDATE keys
        SET upload_total = upload_total + ?,
            download_total = download_total + ?
        WHERE id = ?
        """,
        (upload, download, key_id),
    )


async def mark_seen(db: aiosqlite.Connection, key_id: str) -> None:
    await db.execute(
        "UPDATE keys SET last_seen_at = ? WHERE id = ?",
        (utcnow(), key_id),
    )
