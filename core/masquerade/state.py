"""Persisted masquerade state.

This is the only mutable store of the subsystem. It survives restarts, which
is what makes the active upstream stable: the engine reads it before probing
anything, so a reboot does not silently move the server to another upstream.

Kept in JSON next to the admin config but written only by the engine, so a
human editing ``masquerade.json`` can never corrupt the measurement history.
"""

from __future__ import annotations

import json
import logging
import os
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .config import Paths
from .models import (
    HEALTHY,
    UNHEALTHY,
    UNKNOWN,
    Decision,
    Evaluation,
    ProbeResult,
    Sample,
    iso,
    parse_iso,
    utc_now,
)

log = logging.getLogger(__name__)

STATE_VERSION = 1
MAX_SAMPLES_PER_CANDIDATE = 40
MAX_DECISIONS = 100


def _empty_meta() -> dict[str, Any]:
    return {
        "last_success": None,
        "last_failure": None,
        "latency_ms": 0.0,
        "health": UNKNOWN,
        "consecutive_failures": 0,
        "availability": 0.0,
        "score": 0.0,
    }


@dataclass
class MasqState:
    version: int = STATE_VERSION
    mode: str = "file"
    candidate: str | None = None
    pending_switch: dict[str, Any] | None = None
    history: dict[str, list[Sample]] = field(default_factory=dict)
    candidates: dict[str, dict[str, Any]] = field(default_factory=dict)
    decisions: list[Decision] = field(default_factory=list)
    updated_at: str | None = None
    last_cycle_at: str | None = None
    last_error: str = ""

    # -- accessors --------------------------------------------------------- #

    def samples(self, candidate_id: str) -> list[Sample]:
        return list(self.history.get(candidate_id, ()))

    def meta(self, candidate_id: str) -> dict[str, Any]:
        return dict(self.candidates.get(candidate_id) or _empty_meta())

    def consecutive_failures(self, candidate_id: str) -> int:
        value = self.meta(candidate_id).get("consecutive_failures", 0)
        return int(value or 0)

    def last_probe_at(self) -> str | None:
        newest: datetime | None = None
        for samples in self.history.values():
            for sample in samples:
                moment = parse_iso(sample.at)
                if moment is not None and (newest is None or moment > newest):
                    newest = moment
        return iso(newest)

    # -- mutations --------------------------------------------------------- #

    def record_cycle(self, candidate_id: str, probes: list[ProbeResult]) -> int:
        """Store the probes of one monitoring cycle for one candidate.

        Returns the new consecutive-failure counter. The counter counts
        *cycles*, not individual attempts: a cycle already retries internally,
        so one failed cycle means the upstream failed several times in a row.
        """
        history = self.history.setdefault(candidate_id, [])
        for probe in probes:
            history.append(Sample.from_probe(probe))
        if len(history) > MAX_SAMPLES_PER_CANDIDATE:
            del history[: len(history) - MAX_SAMPLES_PER_CANDIDATE]

        meta = self.candidates.setdefault(candidate_id, _empty_meta())
        latest = probes[-1] if probes else None
        if latest is not None:
            meta["latency_ms"] = round(latest.total_ms, 1) if latest.ok else 0.0

        if probes and any(probe.ok for probe in probes):
            meta["last_success"] = iso(utc_now())
            meta["consecutive_failures"] = 0
        else:
            meta["last_failure"] = iso(utc_now())
            meta["consecutive_failures"] = int(meta.get("consecutive_failures", 0)) + 1

        return int(meta["consecutive_failures"])

    def apply_evaluation(self, evaluation: Evaluation) -> None:
        meta = self.candidates.setdefault(evaluation.candidate_id, _empty_meta())
        meta.update(
            {
                "health": evaluation.health,
                "availability": round(evaluation.availability, 3),
                "score": round(evaluation.score, 4),
                "latency_ms": round(evaluation.mean_latency_ms, 1),
                "last_success": evaluation.last_success or meta.get("last_success"),
                "last_failure": evaluation.last_failure or meta.get("last_failure"),
            }
        )

    def set_active(self, candidate_id: str | None, mode: str) -> None:
        self.candidate = candidate_id
        self.mode = mode
        self.pending_switch = None

    def remember_pending_switch(self, candidate_id: str, score: float) -> int:
        """Track a candidate that keeps beating the active one.

        Returns the number of consecutive cycles it has been winning. The
        selection itself only switches once that count reaches the configured
        confirmation threshold, which is what stops the engine from trading a
        healthy upstream for a marginally faster one every hour.
        """
        pending = self.pending_switch or {}
        if pending.get("id") == candidate_id:
            count = int(pending.get("count", 0)) + 1
            score_max = max(float(pending.get("score", 0.0)), score)
        else:
            count = 1
            score_max = score
        self.pending_switch = {
            "id": candidate_id,
            "count": count,
            "score": round(score_max, 4),
        }
        return count

    def clear_pending_switch(self) -> None:
        self.pending_switch = None

    def add_decision(self, decision: Decision) -> None:
        self.decisions.append(decision)
        if len(self.decisions) > MAX_DECISIONS:
            del self.decisions[: len(self.decisions) - MAX_DECISIONS]

    def prune(self, known_ids: set[str]) -> None:
        for candidate_id in list(self.history):
            if candidate_id not in known_ids:
                del self.history[candidate_id]
        for candidate_id in list(self.candidates):
            if candidate_id not in known_ids:
                del self.candidates[candidate_id]
        if self.candidate and self.candidate not in known_ids:
            self.candidate = None

    # -- serialisation ----------------------------------------------------- #

    def to_json(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "mode": self.mode,
            "candidate": self.candidate,
            "pending_switch": self.pending_switch,
            "history": {
                candidate_id: [sample.to_json() for sample in samples]
                for candidate_id, samples in self.history.items()
            },
            "candidates": self.candidates,
            "decisions": [decision.to_json() for decision in self.decisions],
            "updated_at": self.updated_at,
            "last_cycle_at": self.last_cycle_at,
            "last_error": self.last_error,
        }

    @classmethod
    def from_json(cls, payload: Any) -> MasqState:
        if not isinstance(payload, dict):
            return cls()
        history: dict[str, list[Sample]] = {}
        raw_history = payload.get("history") or {}
        if isinstance(raw_history, dict):
            for candidate_id, samples in raw_history.items():
                if not isinstance(samples, list):
                    continue
                history[str(candidate_id)] = [
                    Sample.from_json(item) for item in samples if isinstance(item, dict)
                ]
        candidates = payload.get("candidates") or {}
        if not isinstance(candidates, dict):
            candidates = {}
        decisions = [
            Decision.from_json(item)
            for item in (payload.get("decisions") or [])
            if isinstance(item, dict)
        ]
        return cls(
            version=int(payload.get("version", STATE_VERSION)),
            mode=str(payload.get("mode", "file")),
            candidate=payload.get("candidate"),
            pending_switch=payload.get("pending_switch"),
            history=history,
            candidates=candidates,
            decisions=decisions,
            updated_at=payload.get("updated_at"),
            last_cycle_at=payload.get("last_cycle_at"),
            last_error=str(payload.get("last_error", "")),
        )


def load_state(paths: Paths) -> MasqState:
    """Read the state file. A missing or corrupt file means "start fresh"."""
    path = paths.state_file
    if not path.exists():
        return MasqState()
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        log.warning("masquerade state is unreadable (%s); starting fresh", exc)
        return MasqState()
    return MasqState.from_json(payload)


def hand_to_service_user(path: Path, mode: int = 0o640) -> None:
    """Give a file written by root back to the service user.

    The engine runs as root (timer, CLI) but the bot runs as ``hyvpn`` and must
    be able to read *and* update this state. Leaving a root-owned file behind
    would make the bot's next write fail and hide the status from the operator.
    """
    try:
        os.chmod(path, mode)
    except OSError:  # pragma: no cover - unusual filesystem
        log.warning("could not chmod %s", path)
    geteuid = getattr(os, "geteuid", None)
    if geteuid is None or geteuid() != 0 or not hasattr(os, "chown"):
        return
    try:  # pragma: no cover - only on the server
        import grp
        import pwd

        uid = pwd.getpwnam("hyvpn").pw_uid
        gid = grp.getgrnam("hyvpn").gr_gid
        os.chown(path, uid, gid)
    except (ImportError, KeyError, OSError) as exc:  # pragma: no cover
        log.warning("could not chown %s: %s", path, exc)


def save_state(paths: Paths, state: MasqState) -> None:
    """Atomically persist the state."""
    paths.state_dir.mkdir(parents=True, exist_ok=True)
    state.updated_at = iso(utc_now())
    payload = json.dumps(state.to_json(), ensure_ascii=False, indent=2) + "\n"
    tmp = paths.state_file.with_name(paths.state_file.name + ".tmp")
    with open(tmp, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(tmp, paths.state_file)
    hand_to_service_user(paths.state_file)


def append_decision_log(paths: Paths, entry: dict[str, Any]) -> None:
    """Append one JSON line to ``decisions.log`` for the operator."""
    try:
        paths.state_dir.mkdir(parents=True, exist_ok=True)
        with open(paths.log_file, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry, ensure_ascii=False) + "\n")
        hand_to_service_user(paths.log_file)
    except OSError as exc:  # pragma: no cover - log failures are not fatal
        log.warning("could not write %s: %s", paths.log_file, exc)


@contextmanager
def exclusive_lock(paths: Paths) -> Iterator[None]:
    """Serialise engine runs (timer, CLI apply, bot request) on one host.

    ``fcntl`` does not exist on Windows, where the subsystem is only ever
    exercised by unit tests, so the lock degrades to a no-op there.
    """
    try:
        import fcntl
    except ImportError:  # pragma: no cover - Windows development
        yield
        return

    paths.state_dir.mkdir(parents=True, exist_ok=True)
    lock_path = paths.state_dir / "engine.lock"
    handle = open(lock_path, "a+", encoding="utf-8")
    try:
        try:  # pragma: no cover - exercised on the server
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            log.warning("another masquerade run holds the lock; waiting")
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        yield
    finally:
        try:  # pragma: no cover
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        finally:
            handle.close()


def health_of(meta: dict[str, Any]) -> str:
    return str(meta.get("health") or UNKNOWN)


def is_healthy(meta: dict[str, Any]) -> bool:
    return health_of(meta) == HEALTHY


def is_unhealthy(meta: dict[str, Any]) -> bool:
    return health_of(meta) == UNHEALTHY


def now_utc_iso() -> str:
    return iso(datetime.now(timezone.utc)) or ""
