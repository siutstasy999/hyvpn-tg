"""A tiny request queue between the unprivileged bot and a root worker.

The bot runs as ``hyvpn`` and must never be able to restart systemd units or
write ``/etc/hyvpn``. Instead of granting it sudo, an apply request is dropped
into a directory that only the bot can write to; a systemd path unit notices
the file and starts a root oneshot service that executes exactly the request
kinds implemented here.

That keeps the privilege boundary at systemd instead of a sudoers rule, and
the request format is fixed — there is no way to smuggle a shell command
through it.
"""

from __future__ import annotations

import json
import logging
import os
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .config import Paths
from .models import iso, parse_iso
from .state import hand_to_service_user

log = logging.getLogger(__name__)

KINDS = ("optimize", "set-mode", "check", "test-candidates")
MAX_REQUEST_BYTES = 4096
MAX_AGE_SECONDS = 900
MAX_RESULTS = 20


@dataclass
class Request:
    id: str
    kind: str
    payload: dict[str, Any]
    requested_by: int | None
    created_at: str
    path: Path

    def to_json(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "kind": self.kind,
            "payload": self.payload,
            "requested_by": self.requested_by,
            "created_at": self.created_at,
        }


def results_dir(paths: Paths) -> Path:
    return paths.state_dir / "results"


def submit(
    paths: Paths,
    kind: str,
    *,
    payload: dict[str, Any] | None = None,
    requested_by: int | None = None,
) -> str:
    """Queue a request. Returns its id."""
    if kind not in KINDS:
        raise ValueError(f"unknown request kind: {kind}")
    request_id = uuid.uuid4().hex[:12]
    request = {
        "id": request_id,
        "kind": kind,
        "payload": payload or {},
        "requested_by": requested_by,
        "created_at": iso(datetime.now(timezone.utc)),
    }
    paths.request_dir.mkdir(parents=True, exist_ok=True)
    target = paths.request_dir / f"{request_id}.json"
    tmp = target.with_name(target.name + ".tmp")
    with open(tmp, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(request, ensure_ascii=False, indent=2) + "\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.chmod(tmp, 0o640)
    os.replace(tmp, target)
    return request_id


def _parse(path: Path) -> Request | None:
    try:
        if path.stat().st_size > MAX_REQUEST_BYTES:
            log.warning("ignoring oversized request %s", path)
            return None
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        log.warning("ignoring unreadable request %s: %s", path, exc)
        return None
    if not isinstance(payload, dict):
        return None
    kind = str(payload.get("kind", ""))
    if kind not in KINDS:
        log.warning("ignoring request with unknown kind %r", kind)
        return None
    created_at = str(payload.get("created_at", ""))
    moment = parse_iso(created_at)
    if moment is not None:
        age = (datetime.now(timezone.utc) - moment).total_seconds()
        if age > MAX_AGE_SECONDS:
            log.warning("ignoring stale request %s (%.0f s old)", path.name, age)
            return None
    requested_by = payload.get("requested_by")
    return Request(
        id=str(payload.get("id") or path.stem),
        kind=kind,
        payload=payload.get("payload") if isinstance(payload.get("payload"), dict) else {},
        requested_by=int(requested_by) if isinstance(requested_by, int) else None,
        created_at=created_at,
        path=path,
    )


def load_pending(paths: Paths) -> list[Request]:
    if not paths.request_dir.is_dir():
        return []
    requests: list[Request] = []
    # Oldest first: a burst of requests (check, then apply) must be executed in
    # the order the administrator pressed the buttons.
    try:
        files = sorted(
            paths.request_dir.glob("*.json"), key=lambda item: item.stat().st_mtime
        )
    except OSError:  # pragma: no cover - concurrent removal
        return []
    for path in files:
        request = _parse(path)
        if request is not None:
            requests.append(request)
    return requests


def discard(request: Request) -> None:
    try:
        request.path.unlink()
    except OSError as exc:  # pragma: no cover - concurrent removal
        log.warning("could not remove request %s: %s", request.path, exc)


def write_result(paths: Paths, request: Request, result: dict[str, Any]) -> Path:
    directory = results_dir(paths)
    directory.mkdir(parents=True, exist_ok=True)
    payload = {
        "request": request.to_json(),
        "finished_at": iso(datetime.now(timezone.utc)),
        "result": result,
    }
    target = directory / f"{request.id}.json"
    tmp = target.with_name(target.name + ".tmp")
    with open(tmp, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(payload, ensure_ascii=False, indent=2) + "\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(tmp, target)
    # The worker runs as root; the bot has to be able to read the outcome.
    hand_to_service_user(target)
    _prune_results(directory)
    return target


def read_results(paths: Paths, limit: int = 5) -> list[dict[str, Any]]:
    directory = results_dir(paths)
    if not directory.is_dir():
        return []
    files = sorted(directory.glob("*.json"), key=lambda item: item.stat().st_mtime)
    results: list[dict[str, Any]] = []
    for path in files[-limit:]:
        try:
            results.append(json.loads(path.read_text(encoding="utf-8")))
        except (OSError, json.JSONDecodeError):
            continue
    return list(reversed(results))


def _prune_results(directory: Path) -> None:
    try:
        files = sorted(directory.glob("*.json"), key=lambda item: item.stat().st_mtime)
    except OSError:  # pragma: no cover
        return
    for stale in files[:-MAX_RESULTS]:
        try:
            stale.unlink()
        except OSError:  # pragma: no cover
            pass
