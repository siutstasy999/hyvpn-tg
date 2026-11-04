"""Persisted state: history, counters, decisions, and crash tolerance."""

from __future__ import annotations

import json

from core.masquerade.models import Sample
from core.masquerade.state import (
    MAX_DECISIONS,
    MasqState,
    append_decision_log,
    load_state,
    save_state,
)
from tests.masq_fakes import make_paths, probe_result


def test_state_round_trips(tmp_path):
    paths = make_paths(tmp_path)
    state = MasqState(mode="proxy", candidate="own")
    state.record_cycle("own", [probe_result("own")])
    state.remember_pending_switch("fast", 0.9)
    save_state(paths, state)

    restored = load_state(paths)
    assert restored.mode == "proxy"
    assert restored.candidate == "own"
    assert restored.consecutive_failures("own") == 0
    assert len(restored.samples("own")) == 1
    assert restored.pending_switch == {"id": "fast", "count": 1, "score": 0.9}


def test_a_missing_state_file_starts_fresh(tmp_path):
    assert load_state(make_paths(tmp_path)).candidate is None


def test_a_corrupt_state_file_does_not_crash_the_engine(tmp_path):
    paths = make_paths(tmp_path)
    paths.state_dir.mkdir(parents=True, exist_ok=True)
    paths.state_file.write_text("{broken json", encoding="utf-8")
    state = load_state(paths)
    assert state.candidate is None
    assert state.history == {}


def test_state_survives_a_writer_crash(tmp_path):
    paths = make_paths(tmp_path)
    paths.state_dir.mkdir(parents=True, exist_ok=True)
    (paths.state_dir / "state.json.tmp").write_text("partial", encoding="utf-8")
    state = MasqState(mode="file")
    save_state(paths, state)
    assert load_state(paths).mode == "file"
    assert not (paths.state_dir / "state.json.tmp").exists()


def test_failed_cycles_increment_and_success_resets():
    state = MasqState()
    assert state.record_cycle("a", [probe_result("a", ok=False)]) == 1
    assert state.record_cycle("a", [probe_result("a", ok=False)]) == 2
    assert state.record_cycle("a", [probe_result("a")]) == 0
    assert state.meta("a")["last_success"]
    assert len(state.samples("a")) == 3


def test_history_is_capped():
    state = MasqState()
    for _ in range(100):
        state.record_cycle("a", [probe_result("a")])
    assert len(state.samples("a")) == 40


def test_prune_removes_unknown_candidates():
    state = MasqState(candidate="gone")
    state.record_cycle("gone", [probe_result("gone")])
    state.record_cycle("kept", [probe_result("kept")])
    state.prune({"kept"})
    assert state.candidate is None
    assert state.samples("gone") == []
    assert state.samples("kept")


def test_decisions_are_capped():
    from core.masquerade.models import Decision

    state = MasqState()
    for index in range(MAX_DECISIONS + 5):
        state.add_decision(
            Decision(at=str(index), mode="file", candidate=None, reason="x", changed=False)
        )
    assert len(state.decisions) == MAX_DECISIONS


def test_decision_log_is_json_lines(tmp_path):
    paths = make_paths(tmp_path)
    append_decision_log(paths, {"mode": "file", "changed": False})
    append_decision_log(paths, {"mode": "proxy", "changed": True})
    lines = paths.log_file.read_text(encoding="utf-8").strip().splitlines()
    assert [json.loads(line)["mode"] for line in lines] == ["file", "proxy"]


def test_last_probe_at_uses_the_newest_sample(tmp_path):
    paths = make_paths(tmp_path)
    state = MasqState()
    state.history["a"] = [
        Sample(at="2026-11-05T10:00:00+00:00", ok=True, total_ms=100),
        Sample(at="2026-11-05T12:00:00+00:00", ok=True, total_ms=100),
    ]
    save_state(paths, state)
    assert load_state(paths).last_probe_at() == "2026-11-05T12:00:00+00:00"
