"""Scoring: deterministic, history based, and hard to game with one probe."""

from __future__ import annotations

import pytest

from core.masquerade.models import Sample, Thresholds
from core.masquerade.scoring import (
    evaluate_candidate,
    latency_score,
    rank_key,
    redirect_score,
    stability_score,
)
from tests.masq_fakes import candidate, evaluation

THRESHOLDS = Thresholds()


def samples(
    pattern: list[tuple[bool, float]],
    *,
    redirects: tuple[str, ...] = (),
    error_kind: str = "connect",
) -> list[Sample]:
    result = []
    for index, (ok, total_ms) in enumerate(pattern):
        result.append(
            Sample(
                at=f"2026-11-05T10:{index:02d}:00+00:00",
                ok=ok,
                status=200 if ok else None,
                total_ms=total_ms,
                error_kind="" if ok else error_kind,
                redirects=redirects if ok else (),
            )
        )
    return result


def evaluate(pattern, **kwargs):
    return evaluate_candidate(
        candidate("a"),
        samples(pattern, **kwargs),
        consecutive_failures=0,
        thresholds=THRESHOLDS,
    )


def test_never_probed_candidate_is_unknown_and_ineligible():
    result = evaluate_candidate(
        candidate("a"), [], consecutive_failures=0, thresholds=THRESHOLDS
    )
    assert result.health == "unknown"
    assert result.score == 0
    assert not result.eligible
    assert not result.retain_ok


def test_a_full_history_of_successes_is_healthy():
    result = evaluate([(True, 150)] * 5)
    assert result.health == "healthy"
    assert result.eligible
    assert result.retain_ok
    assert result.availability == 1.0
    assert result.score > 0.9


def test_one_success_is_not_a_track_record():
    result = evaluate([(True, 150)])
    assert result.health == "degraded"
    assert not result.eligible
    assert result.retain_ok  # it answers correctly right now
    assert "warming up" in " ".join(result.reasons)


def test_latest_failure_makes_a_candidate_unhealthy():
    result = evaluate([(True, 150)] * 4 + [(False, 0)])
    assert result.health == "unhealthy"
    assert not result.eligible
    assert not result.retain_ok
    assert "last probe failed" in " ".join(result.reasons)


def test_consecutive_failed_cycles_block_selection_even_if_the_last_probe_passed():
    result = evaluate_candidate(
        candidate("a"),
        samples([(True, 150)] * 5),
        consecutive_failures=2,
        thresholds=THRESHOLDS,
    )
    assert result.health == "unhealthy"
    assert not result.eligible


def test_availability_below_the_threshold_blocks_selection():
    pattern = [(True, 150)] * 3 + [(False, 0)] * 4 + [(True, 150)] * 3
    result = evaluate(pattern)
    assert result.availability == pytest.approx(0.6)
    assert result.health == "unhealthy"
    assert "availability" in " ".join(result.reasons)


def test_availability_at_the_threshold_is_accepted():
    pattern = [(False, 0)] * 2 + [(True, 150)] * 8
    result = evaluate(pattern)
    assert result.availability == pytest.approx(0.8)
    assert result.health == "healthy"


def test_recovery_after_an_outage_is_recognised():
    # The failures are still in the news, but they have rolled out of the
    # window, so the candidate is healthy again.
    pattern = [(False, 0)] * 5 + [(True, 140)] * 10
    result = evaluate(pattern)
    assert result.samples == THRESHOLDS.window
    assert result.health == "healthy"
    assert result.eligible
    assert result.consecutive_failures == 0


def test_latency_lowers_the_score():
    fast = evaluate([(True, 120)] * 5)
    slow = evaluate([(True, 2300)] * 5)
    assert fast.score > slow.score
    assert slow.score < fast.score - 0.2
    assert slow.health != "unhealthy"


def test_latency_curve_is_piecewise():
    thresholds = Thresholds()
    assert latency_score(100, thresholds) == 1.0
    assert latency_score(thresholds.latency_good_ms, thresholds) == 1.0
    assert latency_score(thresholds.latency_bad_ms, thresholds) == 0.0
    middle = latency_score(
        (thresholds.latency_good_ms + thresholds.latency_bad_ms) / 2, thresholds
    )
    assert 0.0 < middle < 1.0
    assert latency_score(0, thresholds) == 0.0


def test_jitter_is_penalised():
    steady = stability_score([150, 150, 150, 150])
    jittery = stability_score([100, 2000, 120, 1800])
    assert steady == 1.0
    assert jittery < steady


def test_unstable_redirects_degrade_a_candidate():
    first = evaluate(
        [(True, 150)] * 5, redirects=("https://a.example/",)
    )
    assert first.health == "healthy"
    # Two different chains in the window: no longer healthy, still reachable.
    chain_a = ("https://a.example/",)
    chain_b = ("https://b.example/",)
    mixed = evaluate_candidate(
        candidate("a"),
        [
            *(Sample(at="1", ok=True, total_ms=150, redirects=chain_a) for _ in range(3)),
            *(Sample(at="2", ok=True, total_ms=150, redirects=chain_b) for _ in range(3)),
        ],
        consecutive_failures=0,
        thresholds=THRESHOLDS,
    )
    assert mixed.redirect_chains == 2
    assert mixed.health == "degraded"
    assert not mixed.eligible
    assert "redirect chains" in " ".join(mixed.reasons)
    assert redirect_score(1) == 1.0
    assert redirect_score(2) == 0.5


def test_tls_failures_lower_the_tls_factor():
    with_tls_errors = evaluate(
        [(True, 150)] * 8 + [(False, 0)] * 2, error_kind="tls_certificate"
    )
    without = evaluate([(True, 150)] * 8 + [(False, 0)] * 2)
    assert with_tls_errors.score < without.score
    assert "TLS failure" in " ".join(with_tls_errors.reasons)


def test_score_is_deterministic():
    first = evaluate([(True, 120)] * 10)
    second = evaluate([(True, 120)] * 10)
    assert first == second


def test_ranking_prefers_eligible_then_score_then_priority():
    high = evaluation("high", score=0.9)
    low = evaluation("low", score=0.6)
    ineligible = evaluation("bad", score=0.99, eligible=False)
    ordered = sorted(
        [low, ineligible, high],
        key=lambda item: rank_key(item, 0),
    )
    assert [item.candidate_id for item in ordered] == ["high", "low", "bad"]

    tied_a = evaluation("a", score=0.8)
    tied_b = evaluation("b", score=0.8)
    # A higher operator priority wins a tie (it sorts first).
    assert rank_key(tied_b, 10) < rank_key(tied_a, 0)


@pytest.mark.parametrize(
    "payload",
    [
        {"min_samples": 0},
        {"window": 1, "min_samples": 5},
        {"latency_good_ms": 900, "latency_bad_ms": 800},
        {"unknown_setting": 1},
    ],
)
def test_invalid_thresholds_are_rejected(payload):
    with pytest.raises(ValueError):
        Thresholds.from_json(payload)


def test_weights_are_normalised():
    thresholds = Thresholds(
        weight_tls=2, weight_http=2, weight_latency=2, weight_stability=2, weight_redirects=2
    )
    weights = thresholds.normalised_weights()
    assert sum(weights.values()) == pytest.approx(1.0)
    assert weights["tls"] == pytest.approx(0.2)


def test_zero_weights_fall_back_to_equal_shares():
    thresholds = Thresholds(
        weight_tls=0, weight_http=0, weight_latency=0, weight_stability=0, weight_redirects=0
    )
    weights = thresholds.normalised_weights()
    assert weights["tls"] == pytest.approx(0.2)
