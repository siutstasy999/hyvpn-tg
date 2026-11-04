"""Choosing what the server should do next.

The decision is a pure function of (configuration, persisted state, fresh
evaluations). It never phones home, never applies anything and never mutates
its inputs, so ``optimize --dry-run`` and the background monitor run exactly
the same code path.

Two different time constants matter here:

* **Failover** is fast. One monitoring cycle already retries the probe twice,
  so a failed cycle is a real outage; the engine moves to a validated
  alternative (or the local fallback site) immediately instead of leaving the
  configuration pointed at a dead upstream.
* **Optimisation** is slow. Replacing a working upstream with a faster one
  requires the challenger to be ahead by ``switch_margin`` for
  ``switch_confirmations`` consecutive cycles, and it must have a full probe
  history. That is the hysteresis that stops an hourly configuration flap.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .config import MasqConfig
from .models import Candidate, Evaluation, Thresholds
from .scoring import rank_key
from .state import MasqState


@dataclass
class Plan:
    """What the engine intends to do, and why."""

    mode: str
    candidate: Candidate | None
    reason: str
    changed: bool
    previous_mode: str
    previous_candidate: str | None
    evaluations: list[Evaluation] = field(default_factory=list)
    changes: list[str] = field(default_factory=list)
    blocked: bool = False
    pending_switch: dict[str, Any] | None = None

    @property
    def upstream(self) -> str | None:
        return self.candidate.url if self.candidate else None

    @property
    def candidate_id(self) -> str | None:
        return self.candidate.id if self.candidate else None

    def to_json(self) -> dict[str, Any]:
        return {
            "mode": self.mode,
            "candidate": self.candidate_id,
            "upstream": self.upstream,
            "reason": self.reason,
            "changed": self.changed,
            "blocked": self.blocked,
            "previous_mode": self.previous_mode,
            "previous_candidate": self.previous_candidate,
            "changes": list(self.changes),
            "pending_switch": self.pending_switch,
            "evaluations": [evaluation.to_json() for evaluation in self.evaluations],
        }


def _ranked(config: MasqConfig, evaluations: dict[str, Evaluation]) -> list[Candidate]:
    """Enabled candidates that passed validation, best first (deterministic)."""
    eligible = [
        candidate
        for candidate in config.enabled_candidates()
        if (evaluation := evaluations.get(candidate.id)) is not None
        and evaluation.eligible
    ]
    return sorted(
        eligible,
        key=lambda candidate: rank_key(
            evaluations[candidate.id], candidate.priority
        ),
    )


def _plan_for(
    *,
    mode: str,
    candidate: Candidate | None,
    reason: str,
    previous_mode: str,
    previous_candidate: str | None,
    evaluations: list[Evaluation],
    pending_switch: dict[str, Any] | None = None,
    blocked: bool = False,
) -> Plan:
    chosen_id = candidate.id if candidate else None
    if mode == "proxy":
        changed = previous_mode != "proxy" or previous_candidate != chosen_id
    else:
        changed = previous_mode != mode or previous_candidate is not None

    changes: list[str] = []
    if previous_mode != mode:
        changes.append(f"mode: {previous_mode} -> {mode}")
    if mode == "proxy" and previous_candidate != chosen_id:
        changes.append(f"upstream: {previous_candidate or 'none'} -> {chosen_id}")

    if blocked:
        # A blocked plan is a refusal to change anything; reporting it as a
        # pending change would make callers try to apply it.
        changed = False
        changes = []

    return Plan(
        mode=mode,
        candidate=candidate,
        reason=reason,
        changed=changed,
        previous_mode=previous_mode,
        previous_candidate=previous_candidate,
        evaluations=evaluations,
        changes=changes,
        blocked=blocked,
        pending_switch=pending_switch,
    )


def decide(
    config: MasqConfig,
    state: MasqState,
    evaluations: dict[str, Evaluation],
    *,
    previous_mode: str,
    previous_candidate: str | None,
) -> Plan:
    """Return the next configuration to render."""
    thresholds: Thresholds = config.thresholds
    all_evaluations = list(evaluations.values())

    # ---- manual override ------------------------------------------------ #
    if config.mode != "auto":
        if config.mode != "proxy":
            return _plan_for(
                mode=config.mode,
                candidate=None,
                reason=f"mode {config.mode!r} is set explicitly in masquerade.json",
                previous_mode=previous_mode,
                previous_candidate=previous_candidate,
                evaluations=all_evaluations,
            )

        active = config.candidate(state.candidate or previous_candidate or "")
        if active is not None and not active.enabled:
            active = None
        active_eval = evaluations.get(active.id) if active else None
        if active is not None and active_eval is not None and active_eval.retain_ok:
            return _plan_for(
                mode="proxy",
                candidate=active,
                reason="manual proxy mode: the configured upstream answers correctly",
                previous_mode=previous_mode,
                previous_candidate=previous_candidate,
                evaluations=all_evaluations,
            )
        ranked = _ranked(config, evaluations)
        if ranked:
            return _plan_for(
                mode="proxy",
                candidate=ranked[0],
                reason=(
                    "manual proxy mode: the previous upstream is not usable, "
                    "selecting the best validated candidate"
                ),
                previous_mode=previous_mode,
                previous_candidate=previous_candidate,
                evaluations=all_evaluations,
            )
        return _plan_for(
            mode="proxy",
            candidate=None,
            reason=(
                "manual proxy mode, but no candidate passed validation: the "
                "current configuration is kept untouched. Add or fix a "
                "candidate, or switch to auto/file mode"
            ),
            previous_mode=previous_mode,
            previous_candidate=previous_candidate,
            evaluations=all_evaluations,
            blocked=True,
        )

    # ---- automatic mode -------------------------------------------------- #
    active = config.candidate(state.candidate or previous_candidate or "")
    if active is not None and not active.enabled:
        active = None
    active_eval = evaluations.get(active.id) if active else None
    ranked = _ranked(config, evaluations)
    best = ranked[0] if ranked else None

    if active is not None and active_eval is None:
        return _plan_for(
            mode="proxy",
            candidate=active,
            reason=(
                "the active upstream was not probed in this run; keeping the "
                "current configuration"
            ),
            previous_mode=previous_mode,
            previous_candidate=previous_candidate,
            evaluations=all_evaluations,
        )

    if active is not None and active_eval is not None:
        if active_eval.retain_ok:
            challenger = best if best is not None and best.id != active.id else None
            if challenger is not None:
                challenger_eval = evaluations[challenger.id]
                lead = challenger_eval.score - active_eval.score
                pending = state.pending_switch or {}
                count = (
                    int(pending.get("count", 0)) + 1
                    if pending.get("id") == challenger.id
                    else 1
                )
                if (
                    lead >= thresholds.switch_margin
                    and count >= thresholds.switch_confirmations
                ):
                    return _plan_for(
                        mode="proxy",
                        candidate=challenger,
                        reason=(
                            f"{challenger.id} scored {challenger_eval.score:.2f} vs "
                            f"{active_eval.score:.2f} for {count} consecutive "
                            f"cycle(s) (margin {thresholds.switch_margin:.2f}); "
                            "switching to the better upstream"
                        ),
                        previous_mode=previous_mode,
                        previous_candidate=previous_candidate,
                        evaluations=all_evaluations,
                    )
                if lead >= thresholds.switch_margin:
                    return _plan_for(
                        mode="proxy",
                        candidate=active,
                        reason=(
                            f"{challenger.id} leads by {lead:.2f}; keeping "
                            f"{active.id} until the lead is confirmed "
                            f"({count}/{thresholds.switch_confirmations} cycles)"
                        ),
                        previous_mode=previous_mode,
                        previous_candidate=previous_candidate,
                        evaluations=all_evaluations,
                        pending_switch={
                            "id": challenger.id,
                            "count": count,
                            "score": round(challenger_eval.score, 4),
                        },
                    )
            return _plan_for(
                mode="proxy",
                candidate=active,
                reason=(
                    f"{active.id} is healthy (score {active_eval.score:.2f}, "
                    f"{active_eval.mean_latency_ms:.0f} ms); keeping it"
                ),
                previous_mode=previous_mode,
                previous_candidate=previous_candidate,
                evaluations=all_evaluations,
            )

        # The active upstream is not usable right now.
        failures = max(active_eval.consecutive_failures, 1)
        if failures < max(thresholds.failover_after_failures, 1):
            return _plan_for(
                mode="proxy",
                candidate=active,
                reason=(
                    f"{active.id} failed {failures} cycle(s); keeping it until "
                    f"{thresholds.failover_after_failures} to avoid flapping on "
                    "a single blip"
                ),
                previous_mode=previous_mode,
                previous_candidate=previous_candidate,
                evaluations=all_evaluations,
            )
        detail = "; ".join(active_eval.reasons[:2]) or "probe failed"
        if best is not None:
            return _plan_for(
                mode="proxy",
                candidate=best,
                reason=(
                    f"{active.id} is not usable ({detail}); failing over to "
                    f"{best.id} (score {evaluations[best.id].score:.2f})"
                ),
                previous_mode=previous_mode,
                previous_candidate=previous_candidate,
                evaluations=all_evaluations,
            )
        return _plan_for(
            mode="file",
            candidate=None,
            reason=(
                f"{active.id} is not usable ({detail}) and no alternative "
                "passed validation; serving the local fallback site"
            ),
            previous_mode=previous_mode,
            previous_candidate=previous_candidate,
            evaluations=all_evaluations,
        )

    # No active upstream yet.
    if best is not None:
        return _plan_for(
            mode="proxy",
            candidate=best,
            reason=(
                "no upstream is active; selecting the best validated candidate "
                f"({best.id}, score {evaluations[best.id].score:.2f})"
            ),
            previous_mode=previous_mode,
            previous_candidate=previous_candidate,
            evaluations=all_evaluations,
        )
    return _plan_for(
        mode="file",
        candidate=None,
        reason=(
            "no upstream passed validation; serving the local fallback site so "
            "the port never answers as a broken web server"
        ),
        previous_mode=previous_mode,
        previous_candidate=previous_candidate,
        evaluations=all_evaluations,
    )
