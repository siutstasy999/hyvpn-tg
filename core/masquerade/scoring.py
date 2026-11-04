"""Deterministic scoring of upstream candidates.

The score answers one question only: *how good is this upstream for
masquerading, based on what actually happened during real HTTP probes?*

A reachable port or a completed TLS handshake contributes nothing on its own:
:mod:`core.masquerade.probe` only sets ``ok`` after a 2xx response with a
plausible HTML body, and this module refuses to score a candidate whose latest
probe is not ``ok``. Everything below is a pure function of the probe history,
so the same inputs always produce the same score — no randomness, no clock
reads, no network.
"""

from __future__ import annotations

import math

from .models import (
    DEGRADED,
    HEALTHY,
    UNHEALTHY,
    UNKNOWN,
    Candidate,
    Evaluation,
    Sample,
    Thresholds,
)

# Failure kinds that indicate the TLS layer itself was wrong.
TLS_FAILURES = frozenset({"tls", "tls_certificate"})


def _clamp(value: float, low: float = 0.0, high: float = 1.0) -> float:
    return max(low, min(high, value))


def _mean(values: list[float]) -> float:
    return sum(values) / len(values) if values else 0.0


def _stdev(values: list[float]) -> float:
    if len(values) < 2:
        return 0.0
    average = _mean(values)
    variance = sum((value - average) ** 2 for value in values) / len(values)
    return math.sqrt(variance)


def latency_score(mean_ms: float, thresholds: Thresholds) -> float:
    """1.0 up to ``latency_good_ms``, 0.0 from ``latency_bad_ms``, linear between."""
    if mean_ms <= 0:
        return 0.0
    if mean_ms <= thresholds.latency_good_ms:
        return 1.0
    if mean_ms >= thresholds.latency_bad_ms:
        return 0.0
    span = thresholds.latency_bad_ms - thresholds.latency_good_ms
    return _clamp(1.0 - (mean_ms - thresholds.latency_good_ms) / span)


def stability_score(latencies: list[float]) -> float:
    """Penalise jitter: a steady 900 ms beats a 120 ms / 3 s mix."""
    if not latencies:
        return 0.0
    if len(latencies) == 1:
        return 1.0
    average = _mean(latencies)
    if average <= 0:
        return 0.0
    coefficient = _stdev(latencies) / average
    return _clamp(1.0 - coefficient)


def redirect_score(chains: int) -> float:
    """One stable redirect chain is fine; every extra variant costs score."""
    if chains <= 1:
        return 1.0
    return _clamp(1.0 / chains)


def evaluate_candidate(
    candidate: Candidate,
    samples: list[Sample],
    *,
    consecutive_failures: int,
    thresholds: Thresholds,
    last_success: str | None = None,
    last_failure: str | None = None,
) -> Evaluation:
    """Score one candidate from its recent probe history."""
    window = samples[-thresholds.window :]
    if not window:
        return Evaluation(
            candidate_id=candidate.id,
            url=candidate.url,
            score=0.0,
            eligible=False,
            health=UNKNOWN,
            availability=0.0,
            samples=0,
            successes=0,
            mean_latency_ms=0.0,
            latency_stdev_ms=0.0,
            redirect_chains=0,
            consecutive_failures=consecutive_failures,
            last_success=last_success,
            last_failure=last_failure,
            reasons=("never probed",),
        )

    successes = [sample for sample in window if sample.ok]
    latencies = [sample.total_ms for sample in successes if sample.total_ms > 0]
    availability = len(successes) / len(window)
    latest = window[-1]

    chains = {sample.redirects for sample in successes if sample.redirects}
    tls_failures = sum(1 for sample in window if sample.error_kind in TLS_FAILURES)

    weights = thresholds.normalised_weights()
    http_factor = availability
    tls_factor = _clamp(1.0 - tls_failures / len(window))
    latency = _mean(latencies)
    latency_factor = latency_score(latency, thresholds)
    stability = stability_score(latencies)
    redirect = redirect_score(len(chains)) if chains else 1.0

    score = (
        weights["tls"] * tls_factor
        + weights["http"] * http_factor
        + weights["latency"] * latency_factor
        + weights["stability"] * stability
        + weights["redirects"] * redirect
    )

    reasons: list[str] = []
    hard_failure = False
    confident = len(window) >= thresholds.min_samples
    availability_ok = (not confident) or availability >= thresholds.min_availability

    if not latest.ok:
        hard_failure = True
        detail = latest.error_kind or "probe"
        reasons.append(f"last probe failed ({detail})")
    if consecutive_failures > 0:
        hard_failure = True
        reasons.append(
            f"{consecutive_failures} consecutive failed probe cycle(s)"
        )
    if latest.ok and confident and not availability_ok:
        hard_failure = True
        reasons.append(
            f"availability {availability:.0%} below "
            f"{thresholds.min_availability:.0%}"
        )
    if score < thresholds.min_score:
        reasons.append(f"score {score:.2f} below minimum {thresholds.min_score:.2f}")
    if not confident:
        reasons.append(
            f"warming up: {len(window)} of {thresholds.min_samples} probes"
        )
    if len(chains) > 1:
        reasons.append(f"{len(chains)} different redirect chains observed")
    if tls_failures:
        reasons.append(f"{tls_failures} TLS failure(s) in the last {len(window)} probes")
    if latency:
        reasons.append(f"mean response {latency:.0f} ms")

    if hard_failure:
        health = UNHEALTHY
    elif (
        confident
        and availability_ok
        and score >= thresholds.min_score
        and len(chains) <= 1
    ):
        health = HEALTHY
    else:
        health = DEGRADED

    eligible = health == HEALTHY
    retain_ok = latest.ok and consecutive_failures == 0 and availability_ok

    return Evaluation(
        candidate_id=candidate.id,
        url=candidate.url,
        score=_clamp(score),
        eligible=eligible,
        health=health,
        availability=availability,
        samples=len(window),
        successes=len(successes),
        mean_latency_ms=latency,
        latency_stdev_ms=_stdev(latencies),
        redirect_chains=len(chains),
        consecutive_failures=consecutive_failures,
        last_success=last_success,
        last_failure=last_failure,
        reasons=tuple(reasons),
        latest_ok=latest.ok,
        retain_ok=retain_ok,
        confident=confident,
    )


def rank_key(evaluation: Evaluation, priority: int = 0) -> tuple:
    """Sort key: eligible first, then score, then operator priority, then id.

    Deterministic on purpose — two runs with identical data must pick the same
    candidate, otherwise ``--dry-run`` could disagree with ``--apply``.
    """
    return (
        0 if evaluation.eligible else 1,
        -round(evaluation.score, 4),
        -priority,
        evaluation.candidate_id,
    )
