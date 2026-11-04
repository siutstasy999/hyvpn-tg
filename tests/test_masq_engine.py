"""Engine orchestration with fake collaborators (no network, no systemd)."""

from __future__ import annotations

import json

import pytest

from core.masquerade import site as site_builder
from core.masquerade.config import ConfigError, MasqConfig
from core.masquerade.engine import MasqueradeEngine
from core.masquerade.models import Candidate, Thresholds
from core.masquerade.state import load_state
from tests.masq_fakes import (
    FakeDeployer,
    FakeProber,
    candidate,
    capabilities,
    config,
    make_paths,
    ok,
    probe_result,
    seed_template,
)

# One probe is enough to be eligible: these tests exercise the engine, not the
# "warming up" rule (which has its own tests in test_masq_scoring.py).
FAST = Thresholds(min_samples=1, window=5, switch_margin=0.10, switch_confirmations=3)


def make_engine(tmp_path, *, cfg=None, probes=None, deployer=None, **kwargs):
    paths = make_paths(tmp_path)
    seed_template(paths)
    cfg = cfg if cfg is not None else config(thresholds=FAST)
    prober = FakeProber(probes or {})
    deployer = deployer or FakeDeployer(paths=paths, domain="vpn.example.com")
    engine = MasqueradeEngine(
        paths,
        domain="vpn.example.com",
        config=cfg,
        prober=prober,
        deployer=deployer,
        capabilities=kwargs.pop("capabilities", None) or capabilities(),
        sleep=lambda _s: None,
        **kwargs,
    )
    return engine, paths, prober, deployer


# --------------------------------------------------------------------------- #
# planning
# --------------------------------------------------------------------------- #

def test_no_candidates_plans_the_local_fallback(tmp_path):
    engine, paths, _prober, _deployer = make_engine(tmp_path)
    plan, evaluations, state = engine.plan()
    assert plan.mode == "file"
    assert plan.candidate_id is None
    assert evaluations == {}
    assert state.mode == "file"
    # The state file is the only thing written; no production config exists yet.
    assert not paths.fragment.exists()
    assert load_state(paths).mode == "file"


def test_the_best_healthy_candidate_is_selected(tmp_path):
    cfg = config(candidate("slow"), candidate("fast"), thresholds=FAST)
    probes = {
        "slow": [probe_result("slow", total_ms=900)],
        "fast": [probe_result("fast", total_ms=120)],
    }
    engine, _paths, _prober, _deployer = make_engine(tmp_path, cfg=cfg, probes=probes)
    plan, _evaluations, _state = engine.plan()
    assert plan.mode == "proxy"
    assert plan.candidate_id == "fast"
    assert plan.changed


def test_an_unhealthy_candidate_is_never_selected(tmp_path):
    cfg = config(candidate("bad"), thresholds=FAST)
    probes = {"bad": [probe_result("bad", ok=False, error_kind="tls_certificate")]}
    engine, _paths, _prober, _deployer = make_engine(tmp_path, cfg=cfg, probes=probes)
    plan, evaluations, _state = engine.plan()
    assert plan.mode == "file"
    assert evaluations["bad"].health == "unhealthy"
    assert "local fallback" in plan.reason


def test_failed_probes_are_retried_within_a_cycle(tmp_path):
    cfg = config(candidate("flaky"), thresholds=FAST)
    probes = {
        "flaky": [
            probe_result("flaky", ok=False, error_kind="timeout"),
            probe_result("flaky", total_ms=200),
        ]
    }
    engine, _paths, prober, _deployer = make_engine(tmp_path, cfg=cfg, probes=probes)
    engine.plan()
    assert prober.calls.count("flaky") >= 2


# --------------------------------------------------------------------------- #
# cycles and persistence
# --------------------------------------------------------------------------- #

def test_a_cycle_applies_and_records_the_selection(tmp_path):
    cfg = config(candidate("own"), thresholds=FAST)
    probes = {"own": [probe_result("own")]}
    engine, paths, _prober, deployer = make_engine(tmp_path, cfg=cfg, probes=probes)
    report = engine.cycle(apply=True)
    assert report.plan.candidate_id == "own"
    assert deployer.apply_calls and deployer.apply_calls[0]["mode"] == "proxy"
    assert load_state(paths).candidate == "own"
    assert load_state(paths).mode == "proxy"


def test_a_dry_run_cycle_does_not_apply(tmp_path):
    cfg = config(candidate("own"), thresholds=FAST)
    probes = {"own": [probe_result("own")]}
    engine, _paths, _prober, deployer = make_engine(tmp_path, cfg=cfg, probes=probes)
    engine.cycle(apply=False)
    assert deployer.apply_calls == []


def test_state_persists_across_engines(tmp_path):
    cfg = config(candidate("own"), thresholds=FAST)
    probes = {"own": [probe_result("own")]}
    engine, paths, _prober, _deployer = make_engine(tmp_path, cfg=cfg, probes=probes)
    engine.cycle(apply=True)

    # A brand new engine (a restart of the timer) reads the same state.
    fresh = MasqueradeEngine(
        paths,
        domain="vpn.example.com",
        config=cfg,
        prober=FakeProber({"own": [probe_result("own")]}),
        deployer=FakeDeployer(
            paths=paths, domain="vpn.example.com", mode="proxy", upstream=cfg.candidates[0].url
        ),
        capabilities=engine.capabilities,
        sleep=lambda _s: None,
    )
    status = fresh.status()
    assert status.candidate_id == "own"
    assert status.effective_mode == "proxy"


def test_switch_confirmation_accumulates_across_cycles(tmp_path):
    thresholds = Thresholds(
        min_samples=1, window=5, switch_margin=0.1, switch_confirmations=3
    )
    cfg = config(candidate("own"), candidate("fast"), thresholds=thresholds)
    paths = make_paths(tmp_path)
    seed_template(paths)
    deployer = FakeDeployer(
        paths=paths,
        domain="vpn.example.com",
        mode="proxy",
        upstream=cfg.candidates[0].url,
    )
    engine, paths, _prober, deployer = make_engine(
        tmp_path,
        cfg=cfg,
        probes={
            "own": [probe_result("own", total_ms=1500)],
            "fast": [probe_result("fast", total_ms=100)],
        },
        deployer=deployer,
    )
    engine.cycle(apply=True)
    assert load_state(paths).pending_switch["id"] == "fast"
    assert load_state(paths).pending_switch["count"] == 1
    # The upstream did not change on the first cycle.
    assert deployer.apply_calls == []
    assert deployer.mode == "proxy"

    second = MasqueradeEngine(
        paths,
        domain="vpn.example.com",
        config=cfg,
        prober=FakeProber(
            {
                "own": [probe_result("own", total_ms=1500)],
                "fast": [probe_result("fast", total_ms=100)],
            }
        ),
        deployer=FakeDeployer(
            paths=paths,
            domain="vpn.example.com",
            mode="proxy",
            upstream=cfg.candidates[0].url,
        ),
        capabilities=engine.capabilities,
        sleep=lambda _s: None,
    )
    second.cycle(apply=False)
    assert load_state(paths).pending_switch["count"] == 2


# --------------------------------------------------------------------------- #
# status and checks
# --------------------------------------------------------------------------- #

def test_status_reports_the_running_configuration(tmp_path):
    cfg = config(candidate("own"), thresholds=FAST)
    deployer = FakeDeployer(
        paths=make_paths(tmp_path),
        domain="vpn.example.com",
        mode="proxy",
        upstream=cfg.candidates[0].url,
    )
    engine, paths, _prober, _deployer = make_engine(
        tmp_path, cfg=cfg, deployer=deployer
    )
    site_builder.materialize(paths.site_dir, domain="vpn.example.com")
    status = engine.status()
    assert status.effective_mode == "proxy"
    assert status.candidate_id == "own"
    assert status.fallback_ready
    assert status.candidates_total == 1
    payload = status.to_json()
    assert payload["site_dir"] == str(paths.site_dir)
    assert payload["certificate"] is not None


def test_check_reports_a_missing_fallback_site(tmp_path):
    engine, _paths, _prober, _deployer = make_engine(tmp_path)
    report = engine.check()
    assert report["ok"]
    assert any("not materialised" in warning for warning in report["warnings"])
    assert any("no upstream candidates" in note for note in report["notes"])


def test_check_detects_a_broken_registry(tmp_path):
    paths = make_paths(tmp_path)
    paths.config.parent.mkdir(parents=True, exist_ok=True)
    paths.config.write_text("{not json", encoding="utf-8")
    engine = MasqueradeEngine(paths, domain="vpn.example.com")
    report = engine.check()
    assert not report["ok"]
    assert any("masquerade.json" in problem for problem in report["problems"])


# --------------------------------------------------------------------------- #
# administrative operations
# --------------------------------------------------------------------------- #

def test_config_is_created_once(tmp_path):
    engine, paths, _prober, _deployer = make_engine(tmp_path)
    cfg, created = engine.ensure_config()
    assert created
    assert paths.config.is_file()
    assert cfg.mode == "auto"
    assert cfg.candidates == []
    _again, created_again = engine.ensure_config()
    assert not created_again


def test_candidates_can_be_added_removed_and_disabled(tmp_path):
    engine, paths, _prober, _deployer = make_engine(tmp_path)
    engine.ensure_config()
    engine.reload_config()
    entry = Candidate(id="own-site", url="https://own.example/", priority=5)
    engine.add_candidate(entry)
    assert json.loads(paths.config.read_text(encoding="utf-8"))["candidates"][0]["id"] == "own-site"
    with pytest.raises(ConfigError):
        engine.add_candidate(entry)
    engine.set_candidate_enabled("own-site", False)
    assert engine.config.candidate("own-site").enabled is False
    engine.remove_candidate("own-site")
    assert engine.config.candidates == []
    with pytest.raises(ConfigError):
        engine.remove_candidate("own-site")


def test_invalid_candidate_url_is_rejected_by_the_config(tmp_path):
    engine, _paths, _prober, _deployer = make_engine(tmp_path)
    engine.ensure_config()
    engine.reload_config()
    with pytest.raises(ConfigError):
        engine.add_candidate(Candidate(id="bad", url="http://own.example/"))


def test_set_mode_dry_run_does_not_touch_the_config(tmp_path):
    engine, paths, _prober, deployer = make_engine(tmp_path)
    engine.ensure_config()
    engine.reload_config()
    before = paths.config.read_text(encoding="utf-8")
    report = engine.set_mode("file", dry_run=True)
    assert report.plan.mode == "file"
    assert paths.config.read_text(encoding="utf-8") == before
    assert deployer.apply_calls == []


def test_set_mode_writes_the_config_and_applies(tmp_path):
    engine, paths, _prober, deployer = make_engine(tmp_path)
    engine.ensure_config()
    engine.reload_config()
    report = engine.set_mode("string")
    assert report.plan.mode == "string"
    assert json.loads(paths.config.read_text(encoding="utf-8"))["mode"] == "string"
    assert deployer.apply_calls[0]["mode"] == "string"


def test_set_mode_rejects_unknown_modes(tmp_path):
    engine, _paths, _prober, _deployer = make_engine(tmp_path)
    with pytest.raises(ConfigError):
        engine.set_mode("carrier-pigeon")


def test_init_creates_config_and_site(tmp_path):
    engine, paths, _prober, deployer = make_engine(tmp_path)
    report = engine.init(restart=False)
    assert report.config_created
    assert paths.config.is_file()
    assert site_builder.is_current(paths.site_dir, "vpn.example.com")
    assert report.deployment is not None
    assert deployer.apply_calls[0]["mode"] == "file"


def test_init_is_idempotent(tmp_path):
    engine, paths, _prober, _deployer = make_engine(tmp_path)
    engine.init(restart=False)
    engine2, _paths2, _prober2, deployer2 = make_engine(tmp_path)
    report = engine2.init(restart=False)
    assert report.config_created is False
    assert report.site_files_written == []
    assert deployer2.apply_calls == []


def test_decisions_are_logged(tmp_path):
    cfg = config(candidate("own"), thresholds=FAST)
    probes = {"own": [probe_result("own")]}
    engine, paths, _prober, _deployer = make_engine(tmp_path, cfg=cfg, probes=probes)
    engine.cycle(apply=True)
    lines = paths.log_file.read_text(encoding="utf-8").strip().splitlines()
    assert lines
    entry = json.loads(lines[-1])
    assert entry["candidate"] == "own"
    assert entry["mode"] == "proxy"


def test_probes_never_leave_the_window_of_configured_candidates(tmp_path):
    cfg = MasqConfig(mode="auto", candidates=[candidate("a")])
    engine, _paths, prober, _deployer = make_engine(tmp_path, cfg=cfg, probes={})
    engine.plan()
    assert set(prober.calls) == {"a"}


def test_ok_helper_is_available():  # pragma: no cover - sanity for the fakes module
    assert ok().returncode == 0
