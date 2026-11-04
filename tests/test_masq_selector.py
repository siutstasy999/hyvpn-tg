"""Selection: failover fast, optimisation slow, fallback always available."""

from __future__ import annotations

from core.masquerade.models import Thresholds
from core.masquerade.selector import decide
from core.masquerade.state import MasqState
from tests.masq_fakes import candidate, config, evaluation

THRESHOLDS = Thresholds()


def make_state(active: str | None = None, pending: dict | None = None) -> MasqState:
    state = MasqState(mode="proxy", candidate=active)
    state.pending_switch = pending
    return state


def test_healthy_active_candidate_is_kept():
    cfg = config(candidate("own"))
    plan = decide(
        cfg,
        make_state("own"),
        {"own": evaluation("own", score=0.9)},
        previous_mode="proxy",
        previous_candidate="own",
    )
    assert plan.mode == "proxy"
    assert plan.candidate_id == "own"
    assert not plan.changed
    assert "healthy" in plan.reason


def test_failed_active_candidate_fails_over_to_a_validated_alternative():
    cfg = config(candidate("own"), candidate("spare"))
    plan = decide(
        cfg,
        make_state("own"),
        {
            "own": evaluation(
                "own",
                score=0.1,
                eligible=False,
                retain_ok=False,
                latest_ok=False,
                health="unhealthy",
                consecutive_failures=1,
                reasons=("last probe failed (connect)",),
            ),
            "spare": evaluation("spare", score=0.8),
        },
        previous_mode="proxy",
        previous_candidate="own",
    )
    assert plan.candidate_id == "spare"
    assert plan.changed
    assert "not usable" in plan.reason
    assert "upstream: own -> spare" in plan.changes


def test_failed_active_candidate_falls_back_to_local_files():
    cfg = config(candidate("own"))
    plan = decide(
        cfg,
        make_state("own"),
        {
            "own": evaluation(
                "own",
                score=0.0,
                eligible=False,
                retain_ok=False,
                latest_ok=False,
                health="unhealthy",
                consecutive_failures=1,
            )
        },
        previous_mode="proxy",
        previous_candidate="own",
    )
    assert plan.mode == "file"
    assert plan.candidate_id is None
    assert plan.changed
    assert "local fallback" in plan.reason
    assert "mode: proxy -> file" in plan.changes


def test_failover_waits_for_the_configured_number_of_failures():
    thresholds = Thresholds(failover_after_failures=3)
    cfg = config(candidate("own"), candidate("spare"), thresholds=thresholds)
    plan = decide(
        cfg,
        make_state("own"),
        {
            "own": evaluation(
                "own",
                eligible=False,
                retain_ok=False,
                latest_ok=False,
                health="unhealthy",
                consecutive_failures=1,
            ),
            "spare": evaluation("spare", score=0.8),
        },
        previous_mode="proxy",
        previous_candidate="own",
    )
    assert plan.candidate_id == "own"
    assert not plan.changed
    assert "avoid flapping" in plan.reason


def test_no_candidates_means_local_fallback():
    cfg = config()
    plan = decide(
        cfg,
        make_state(None),
        {},
        previous_mode="proxy",
        previous_candidate="gone",
    )
    assert plan.mode == "file"
    assert plan.changed


def test_first_run_picks_the_best_validated_candidate():
    cfg = config(candidate("a"), candidate("b"))
    plan = decide(
        cfg,
        make_state(None),
        {"a": evaluation("a", score=0.7), "b": evaluation("b", score=0.9)},
        previous_mode="none",
        previous_candidate=None,
    )
    assert plan.candidate_id == "b"
    assert plan.changed
    assert plan.changes == ["mode: none -> proxy", "upstream: none -> b"]


def test_a_better_candidate_needs_confirmed_lead_before_switching():
    thresholds = Thresholds(switch_margin=0.15, switch_confirmations=3)
    cfg = config(candidate("own"), candidate("fast"), thresholds=thresholds)
    evaluations = {
        "own": evaluation("own", score=0.70),
        "fast": evaluation("fast", score=0.95),
    }
    plan = decide(
        cfg,
        make_state("own"),
        evaluations,
        previous_mode="proxy",
        previous_candidate="own",
    )
    assert plan.candidate_id == "own"
    assert not plan.changed
    assert plan.pending_switch["id"] == "fast"
    assert plan.pending_switch["count"] == 1
    assert "1/3" in plan.reason


def test_confirmed_lead_switches_the_upstream():
    thresholds = Thresholds(switch_margin=0.15, switch_confirmations=3)
    cfg = config(candidate("own"), candidate("fast"), thresholds=thresholds)
    plan = decide(
        cfg,
        make_state("own", pending={"id": "fast", "count": 2, "score": 0.95}),
        {"own": evaluation("own", score=0.70), "fast": evaluation("fast", score=0.95)},
        previous_mode="proxy",
        previous_candidate="own",
    )
    assert plan.candidate_id == "fast"
    assert plan.changed
    assert "3 consecutive" in plan.reason


def test_pending_lead_is_reset_by_a_different_challenger():
    thresholds = Thresholds(switch_margin=0.15, switch_confirmations=3)
    cfg = config(candidate("own"), candidate("a"), candidate("b"), thresholds=thresholds)
    plan = decide(
        cfg,
        make_state("own", pending={"id": "a", "count": 2, "score": 0.9}),
        {
            "own": evaluation("own", score=0.70),
            "a": evaluation("a", score=0.72),
            "b": evaluation("b", score=0.95),
        },
        previous_mode="proxy",
        previous_candidate="own",
    )
    assert plan.candidate_id == "own"
    assert plan.pending_switch == {"id": "b", "count": 1, "score": 0.95}


def test_a_marginal_lead_does_not_even_start_a_switch():
    thresholds = Thresholds(switch_margin=0.15, switch_confirmations=1)
    cfg = config(candidate("own"), candidate("fast"), thresholds=thresholds)
    plan = decide(
        cfg,
        make_state("own"),
        {"own": evaluation("own", score=0.80), "fast": evaluation("fast", score=0.85)},
        previous_mode="proxy",
        previous_candidate="own",
    )
    assert plan.candidate_id == "own"
    assert plan.pending_switch is None


def test_disabled_candidates_are_never_selected():
    cfg = config(candidate("own"), candidate("off", enabled=False))
    plan = decide(
        cfg,
        make_state(None),
        {"own": evaluation("own", score=0.4, eligible=False), "off": evaluation("off")},
        previous_mode="none",
        previous_candidate=None,
    )
    assert plan.mode == "file"


def test_removed_active_candidate_is_replaced():
    cfg = config(candidate("spare"))
    plan = decide(
        cfg,
        make_state("deleted"),
        {"spare": evaluation("spare", score=0.7)},
        previous_mode="proxy",
        previous_candidate="deleted",
    )
    assert plan.candidate_id == "spare"


def test_manual_file_mode_ignores_evaluations():
    cfg = config(candidate("own"), mode="file")
    plan = decide(
        cfg,
        make_state("own"),
        {"own": evaluation("own", score=0.99)},
        previous_mode="proxy",
        previous_candidate="own",
    )
    assert plan.mode == "file"
    assert not plan.blocked
    assert plan.changes == ["mode: proxy -> file"]


def test_manual_proxy_mode_without_a_usable_candidate_is_blocked():
    cfg = config(candidate("own"), mode="proxy")
    plan = decide(
        cfg,
        make_state("own"),
        {
            "own": evaluation(
                "own",
                eligible=False,
                retain_ok=False,
                latest_ok=False,
                health="unhealthy",
            )
        },
        previous_mode="proxy",
        previous_candidate="own",
    )
    assert plan.blocked
    assert not plan.changed
    assert "current configuration is kept" in plan.reason


def test_active_candidate_that_was_not_probed_is_left_alone():
    cfg = config(candidate("own"), candidate("fast"))
    plan = decide(
        cfg,
        make_state("own"),
        {"fast": evaluation("fast", score=0.9)},
        previous_mode="proxy",
        previous_candidate="own",
    )
    assert plan.candidate_id == "own"
    assert not plan.changed
    assert "not probed" in plan.reason
