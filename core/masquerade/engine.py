"""Orchestration of the masquerade subsystem.

One engine object ties the pieces together: it loads the configuration, probes
candidates, records observations, asks the selector what to do and — only when
explicitly allowed — deploys the result. The CLI, the Telegram bot and the
systemd timer all go through this class, so they cannot drift apart.

Read-only operations (``status``, ``check``, ``optimize --dry-run``) never
touch the production configuration. Everything that writes is one method:
:meth:`MasqueradeEngine.apply_plan`, which delegates to
:class:`core.masquerade.deploy.Deployer`.
"""

from __future__ import annotations

import json
import logging
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Any

from core.cert_service import CertInfo, get_cert_info

from . import site as site_builder
from .capabilities import Capabilities, detect
from .config import (
    ConfigError,
    MasqConfig,
    Paths,
    default_config,
    load_config,
    write_config,
)
from .deploy import Deployer, DeploymentResult, Http3Result
from .models import (
    EFFECTIVE_MODES,
    Candidate,
    Decision,
    Evaluation,
    ProbeResult,
    iso,
    utc_now,
)
from .probe import Prober
from .render import describe_masquerade, extract_masquerade
from .scoring import evaluate_candidate, rank_key
from .selector import Plan, decide
from .state import (
    MasqState,
    append_decision_log,
    exclusive_lock,
    load_state,
    save_state,
)

log = logging.getLogger(__name__)

MAX_CANDIDATES_PER_CYCLE = 8


@dataclass
class Status:
    """Everything an operator needs to see at a glance."""

    configured_mode: str
    effective_mode: str
    upstream: str | None
    candidate_id: str | None
    candidate_health: str
    last_probe: str | None
    last_latency_ms: float
    last_error: str
    evaluations: list[Evaluation]
    fallback_ready: bool
    certificate: CertInfo | None
    service_active: bool | None
    runtime_mode: str
    fragment_path: str
    site_dir: str
    state_path: str
    config_path: str
    capabilities: Capabilities
    pending_switch: dict[str, Any] | None
    last_cycle_at: str | None
    candidates_enabled: int = 0
    candidates_total: int = 0

    def to_json(self) -> dict[str, Any]:
        return {
            "configured_mode": self.configured_mode,
            "effective_mode": self.effective_mode,
            "upstream": self.upstream,
            "candidate_id": self.candidate_id,
            "candidate_health": self.candidate_health,
            "last_probe": self.last_probe,
            "last_latency_ms": round(self.last_latency_ms, 1),
            "last_error": self.last_error,
            "evaluations": [evaluation.to_json() for evaluation in self.evaluations],
            "fallback_ready": self.fallback_ready,
            "certificate": _cert_json(self.certificate),
            "service_active": self.service_active,
            "runtime_mode": self.runtime_mode,
            "fragment_path": self.fragment_path,
            "site_dir": self.site_dir,
            "state_path": self.state_path,
            "config_path": self.config_path,
            "capabilities": self.capabilities.to_json(),
            "pending_switch": self.pending_switch,
            "last_cycle_at": self.last_cycle_at,
            "candidates_enabled": self.candidates_enabled,
            "candidates_total": self.candidates_total,
        }


@dataclass
class InitReport:
    """Result of :meth:`MasqueradeEngine.init`."""

    config_created: bool
    config_path: str
    site_dir: str
    site_files_written: list[str] = field(default_factory=list)
    existing_mode: str = "none"
    deployment: DeploymentResult | None = None

    def to_json(self) -> dict[str, Any]:
        return {
            "config_created": self.config_created,
            "config_path": self.config_path,
            "site_dir": self.site_dir,
            "site_files_written": list(self.site_files_written),
            "existing_mode": self.existing_mode,
            "deployment": self.deployment.to_json() if self.deployment else None,
        }


@dataclass
class CycleReport:
    at: str
    configured_mode: str
    mode_before: str
    upstream_before: str | None
    plan: Plan
    deployment: DeploymentResult | None
    probes: dict[str, list[ProbeResult]] = field(default_factory=dict)
    dry_run: bool = False
    errors: list[str] = field(default_factory=list)

    def to_json(self) -> dict[str, Any]:
        return {
            "at": self.at,
            "configured_mode": self.configured_mode,
            "mode_before": self.mode_before,
            "upstream_before": self.upstream_before,
            "plan": self.plan.to_json(),
            "deployment": self.deployment.to_json() if self.deployment else None,
            "probes": {
                candidate_id: [probe.to_json() for probe in probes]
                for candidate_id, probes in self.probes.items()
            },
            "dry_run": self.dry_run,
            "errors": self.errors,
        }


def _cert_json(cert: CertInfo | None) -> dict[str, Any] | None:
    if cert is None:
        return None
    try:
        return json.loads(cert.to_json())
    except ValueError:  # pragma: no cover
        return None


class MasqueradeEngine:
    def __init__(
        self,
        paths: Paths,
        *,
        domain: str,
        server_port: int = 443,
        acme_dir: str = "/var/lib/hysteria/acme",
        cert_status_path: str = "/var/lib/hyvpn/cert.json",
        config: MasqConfig | None = None,
        prober: Prober | None = None,
        deployer: Deployer | None = None,
        capabilities: Capabilities | None = None,
        runner: Callable[..., Any] | None = None,
        sleep: Callable[[float], None] = time.sleep,
    ):
        self.paths = paths
        self.domain = domain
        self.server_port = server_port
        self.acme_dir = acme_dir
        self.cert_status_path = cert_status_path
        self._config = config
        self._prober = prober
        self._deployer = deployer
        self._capabilities = capabilities
        self._runner = runner
        self._sleep = sleep

    # -- lazily built collaborators ---------------------------------------- #

    @property
    def config(self) -> MasqConfig:
        if self._config is None:
            self._config = load_config(self.paths)
        return self._config

    @property
    def capabilities(self) -> Capabilities:
        if self._capabilities is None:
            self._capabilities = detect(str(self.paths.hysteria_binary), self._runner)
        return self._capabilities

    @property
    def prober(self) -> Prober:
        if self._prober is None:
            self._prober = Prober(self.config.thresholds)
        return self._prober

    @property
    def deployer(self) -> Deployer:
        if self._deployer is None:
            self._deployer = Deployer(
                self.paths,
                domain=self.domain,
                config=self.config,
                capabilities=self.capabilities,
                runner=self._runner,
                sleep=self._sleep,
                server_port=self.server_port,
            )
        return self._deployer

    # -- state ------------------------------------------------------------- #

    def load_state(self) -> MasqState:
        state = load_state(self.paths)
        state.prune({candidate.id for candidate in self.config.candidates})
        return state

    def save_state(self, state: MasqState) -> None:
        save_state(self.paths, state)

    def _previous(self, state: MasqState) -> tuple[str, str | None]:
        """(effective mode, candidate id) of the *running* configuration."""
        current = self.deployer.current()
        mode = str(current.get("mode") or "none")
        upstream = current.get("upstream")
        candidate_id = self.candidate_id_for_url(upstream) if upstream else None
        if mode == "proxy" and candidate_id is None and state.candidate:
            candidate_id = state.candidate
        if mode not in EFFECTIVE_MODES:
            mode = "none"
        return mode, candidate_id

    def candidate_id_for_url(self, url: str | None) -> str | None:
        if not url:
            return None
        for candidate in self.config.candidates:
            if candidate.url == url:
                return candidate.id
        return None

    # -- probing ----------------------------------------------------------- #

    def probe_all(
        self,
        state: MasqState,
        *,
        candidate_ids: Iterable[str] | None = None,
    ) -> dict[str, list[ProbeResult]]:
        wanted = set(candidate_ids) if candidate_ids is not None else None
        enabled = [
            candidate
            for candidate in self.config.enabled_candidates()
            if wanted is None or candidate.id in wanted
        ]
        if len(enabled) > MAX_CANDIDATES_PER_CYCLE:
            log.warning(
                "probing only the first %d of %d candidates",
                MAX_CANDIDATES_PER_CYCLE,
                len(enabled),
            )
            enabled = enabled[:MAX_CANDIDATES_PER_CYCLE]

        results: dict[str, list[ProbeResult]] = {}
        attempts = max(self.config.thresholds.probe_attempts, 1)
        for candidate in enabled:
            probes: list[ProbeResult] = []
            for attempt in range(1, attempts + 1):
                probe = self.prober.probe(candidate)
                probes.append(probe)
                if probe.ok:
                    break
                if attempt < attempts and self.config.thresholds.retry_delay_seconds > 0:
                    self._sleep(self.config.thresholds.retry_delay_seconds)
            results[candidate.id] = probes
            state.record_cycle(candidate.id, probes)
        return results

    def evaluate(self, state: MasqState) -> dict[str, Evaluation]:
        evaluations: dict[str, Evaluation] = {}
        for candidate in self.config.candidates:
            if not candidate.enabled:
                continue
            meta = state.meta(candidate.id)
            evaluation = evaluate_candidate(
                candidate,
                state.samples(candidate.id),
                consecutive_failures=int(meta.get("consecutive_failures", 0) or 0),
                thresholds=self.config.thresholds,
                last_success=meta.get("last_success"),
                last_failure=meta.get("last_failure"),
            )
            state.apply_evaluation(evaluation)
            evaluations[candidate.id] = evaluation
        return evaluations

    # -- read-only views --------------------------------------------------- #

    def status(self) -> Status:
        state = self.load_state()
        evaluations = self.evaluate(state)
        current = self.deployer.current()
        effective = str(current.get("mode") or "none")
        upstream = current.get("upstream")
        candidate_id = self.candidate_id_for_url(upstream) or state.candidate
        meta = state.meta(candidate_id) if candidate_id else {}

        try:
            service_active: bool | None = self.deployer.service_active()
        except Exception as exc:  # pragma: no cover - defensive
            log.debug("service state unavailable: %s", exc)
            service_active = None
        try:
            certificate: CertInfo | None = get_cert_info(
                self.domain, self.acme_dir, self.cert_status_path
            )
        except Exception as exc:  # pragma: no cover - defensive
            log.debug("certificate info unavailable: %s", exc)
            certificate = CertInfo(domain=self.domain, error=str(exc))

        priorities = {item.id: item.priority for item in self.config.candidates}
        return Status(
            configured_mode=self.config.mode,
            effective_mode=effective,
            upstream=upstream,
            candidate_id=candidate_id,
            candidate_health=str(meta.get("health") or "unknown"),
            last_probe=state.last_probe_at(),
            last_latency_ms=float(meta.get("latency_ms") or 0.0),
            last_error=state.last_error,
            evaluations=sorted(
                evaluations.values(),
                key=lambda item: rank_key(item, priorities.get(item.candidate_id, 0)),
            ),
            fallback_ready=site_builder.is_current(self.paths.site_dir, self.domain),
            certificate=certificate,
            service_active=service_active,
            runtime_mode=self.deployer.runtime_mode(),
            fragment_path=str(self.paths.fragment),
            site_dir=str(self.paths.site_dir),
            state_path=str(self.paths.state_file),
            config_path=str(self.paths.config),
            capabilities=self.capabilities,
            pending_switch=state.pending_switch,
            last_cycle_at=state.last_cycle_at,
            candidates_enabled=len(self.config.enabled_candidates()),
            candidates_total=len(self.config.candidates),
        )

    def check(self, *, persist: bool = False) -> dict[str, Any]:
        """Diagnose the current setup.

        Read-only by default: probes are performed but the measurement history
        is not updated, so ``hyvpn masquerade check`` cannot influence which
        upstream the next monitoring cycle would pick.
        """
        problems: list[str] = []
        warnings: list[str] = []
        notes: list[str] = []

        try:
            config = self.config
            problems.extend(config.validate())
        except ConfigError as exc:
            problems.append(str(exc))
            config = default_config()
        if problems:
            return {
                "ok": False,
                "problems": problems,
                "warnings": warnings,
                "notes": notes,
                "capabilities": self.capabilities.to_json(),
            }

        deployment = self.deployer
        fragment = deployment.fragment_text()
        notes.append(f"fragment: {self.paths.fragment}")
        fragment_mode = "none"
        if not fragment.strip():
            notes.append(
                "no masquerade fragment yet: the server answers 404 to "
                "unauthenticated HTTP requests"
            )
        else:
            section = describe_masquerade(extract_masquerade(fragment))
            fragment_mode = str(section.get("mode") or "none")
            ok, errors, warns, val_notes = deployment.validate(fragment_mode, fragment)
            problems.extend(errors)
            warnings.extend(warns)
            notes.extend(val_notes)
            notes.append(f"fragment mode: {fragment_mode}")
            if ok:
                notes.append("the fragment passes structural validation")

        try:
            active = deployment.service_active()
        except Exception as exc:  # pragma: no cover - defensive
            active = False
            warnings.append(f"could not read the service state: {exc}")
        notes.append(f"{self.paths.service}: {'active' if active else 'not active'}")

        runtime_mode = deployment.runtime_mode()
        if runtime_mode and runtime_mode != fragment_mode:
            warnings.append(
                "the running configuration differs from the managed fragment; "
                "restart the service to apply it (`hyvpn restart hysteria`)"
            )

        fallback_ready = site_builder.is_current(self.paths.site_dir, self.domain)
        notes.append(
            f"fallback site: {'present' if fallback_ready else 'missing'} "
            f"({self.paths.site_dir})"
        )
        if not fallback_ready and config.mode in {"auto", "file"}:
            warnings.append(
                "the local fallback site is not materialised; run "
                "`hyvpn masquerade init`"
            )

        state = self.load_state()
        enabled = config.enabled_candidates()
        notes.append(f"candidates: {len(enabled)} enabled of {len(config.candidates)}")
        if not enabled and config.mode == "auto":
            notes.append(
                "no upstream candidates are configured; the local fallback site "
                "is served. Add one with `hyvpn masquerade candidates add`."
            )
        elif enabled:
            probes = self.probe_all(state)
            evaluations = self.evaluate(state)
            if persist:
                with exclusive_lock(self.paths):
                    self.save_state(state)
            for candidate in enabled:
                evaluation = evaluations.get(candidate.id)
                if evaluation is None:  # pragma: no cover - defensive
                    continue
                notes.append(
                    f"{candidate.id}: {evaluation.health} (score "
                    f"{evaluation.score:.2f}, {evaluation.mean_latency_ms:.0f} ms, "
                    f"{evaluation.samples} sample(s))"
                )
            for candidate_id, probe_results in probes.items():
                last = probe_results[-1]
                if not last.ok:
                    warnings.append(
                        f"{candidate_id}: {last.error_kind or 'probe'} - {last.error}"
                    )

        http3 = self.http3_check()
        if http3 is not None:
            if http3.available and http3.ok:
                notes.append(f"HTTP/3 self-check: {http3.detail}")
            elif http3.available:
                warnings.append(
                    "HTTP/3 self-check failed: the port does not answer the "
                    f"masquerade page over QUIC ({http3.detail})"
                )
            else:
                notes.append(f"HTTP/3 self-check unavailable: {http3.detail}")

        return {
            "ok": not problems,
            "problems": problems,
            "warnings": warnings,
            "notes": notes,
            "http3": http3.to_json() if http3 else None,
            "capabilities": self.capabilities.to_json(),
        }

    def http3_check(self) -> Http3Result | None:
        try:
            return self.deployer.http3_check()
        except Exception as exc:  # pragma: no cover - defensive
            log.debug("HTTP/3 check failed: %s", exc)
            return None

    # -- planning ---------------------------------------------------------- #

    def _collect(
        self,
        state: MasqState,
        *,
        record_decision_state: bool = True,
    ) -> tuple[Plan, dict[str, Evaluation], dict[str, list[ProbeResult]]]:
        probes = self.probe_all(state)
        evaluations = self.evaluate(state)
        previous_mode, previous_candidate = self._previous(state)
        plan = decide(
            self.config,
            state,
            evaluations,
            previous_mode=previous_mode,
            previous_candidate=previous_candidate,
        )
        if record_decision_state:
            if plan.blocked:
                state.last_error = plan.reason
            else:
                state.pending_switch = plan.pending_switch
        return plan, evaluations, probes

    def plan(
        self, *, record_decision_state: bool = True
    ) -> tuple[Plan, dict[str, Evaluation], MasqState]:
        """Probe, decide and persist the measurements — but change nothing.

        ``record_decision_state=False`` keeps a dry run from advancing the
        switch-confirmation counter, so looking at the proposal cannot make the
        background monitor switch sooner.
        """
        with exclusive_lock(self.paths):
            state = self.load_state()
            plan, evaluations, _probes = self._collect(
                state, record_decision_state=record_decision_state
            )
            self.save_state(state)
            return plan, evaluations, state

    def reload_config(self) -> MasqConfig:
        """Re-read the admin config after it was modified on disk."""
        self._config = load_config(self.paths)
        if self._deployer is not None:
            # Keep an injected/real deployer alive but point it at the new
            # config instead of dropping it.
            self._deployer.config = self._config
        return self._config

    # -- applying ---------------------------------------------------------- #

    def apply_plan(
        self, plan: Plan, state: MasqState, *, dry_run: bool = False
    ) -> DeploymentResult:
        if plan.blocked:
            return DeploymentResult(
                mode=plan.mode,
                upstream=plan.upstream,
                notes=[plan.reason],
            )
        if not plan.changed:
            return DeploymentResult(
                mode=plan.mode,
                upstream=plan.upstream,
                notes=[plan.reason],
            )
        result = self.deployer.apply(
            plan.mode,
            upstream_url=plan.upstream,
            reason=plan.reason,
            dry_run=dry_run,
            config=self.config,
        )
        if result.applied and result.verified and not result.rolled_back:
            state.set_active(plan.candidate_id, plan.mode)
            state.last_error = ""
        elif result.errors:
            state.last_error = "; ".join(result.errors[:3])
        decision = Decision(
            at=iso(utc_now()) or "",
            mode=result.mode or plan.mode,
            candidate=plan.candidate_id,
            reason=plan.reason,
            changed=result.changed,
            evaluated=tuple(
                sorted(evaluation.candidate_id for evaluation in plan.evaluations)
            ),
        )
        state.add_decision(decision)
        append_decision_log(
            self.paths,
            {
                "at": decision.at,
                "mode": decision.mode,
                "candidate": decision.candidate,
                "reason": decision.reason,
                "changed": decision.changed,
                "dry_run": dry_run,
                "applied": result.applied,
                "rolled_back": result.rolled_back,
                "errors": result.errors,
            },
        )
        return result

    def cycle(self, *, apply: bool = True, dry_run: bool = False) -> CycleReport:
        """One monitoring cycle: probe, decide, deploy when asked to."""
        with exclusive_lock(self.paths):
            state = self.load_state()
            upstream_before = self.deployer.current().get("upstream")
            plan, _evaluations, probes = self._collect(
                state, record_decision_state=not dry_run
            )
            deployment: DeploymentResult | None = None
            if apply:
                deployment = self.apply_plan(plan, state, dry_run=dry_run)
            self.save_state(state)
        return CycleReport(
            at=iso(utc_now()) or "",
            configured_mode=self.config.mode,
            mode_before=plan.previous_mode,
            upstream_before=upstream_before,
            plan=plan,
            deployment=deployment,
            probes=probes,
            dry_run=dry_run,
            errors=deployment.errors if deployment else [],
        )

    # -- administrative operations ----------------------------------------- #

    def ensure_config(self) -> tuple[MasqConfig, bool]:
        """Create the admin config on first run. Returns (config, created)."""
        if self.paths.config.exists():
            return load_config(self.paths), False
        config = default_config()
        write_config(self.paths, config)
        return config, True

    def ensure_site(self) -> list[str]:
        return site_builder.materialize(self.paths.site_dir, domain=self.domain)

    def init(self, *, restart: bool = True) -> InitReport:
        """Prepare a fresh installation: config, fallback site, initial fragment.

        ``restart=False`` is used by install.sh, where the service is started
        a few steps later by systemd itself.
        """
        with exclusive_lock(self.paths):
            config, created = self.ensure_config()
            self._config = config
            site_changes = self.ensure_site()
            report = InitReport(
                config_created=created,
                config_path=str(self.paths.config),
                site_dir=str(self.paths.site_dir),
                site_files_written=site_changes,
                existing_mode=self.deployer.current_mode(),
            )
            if not self.paths.fragment.exists():
                report.deployment = self.deployer.apply(
                    "file",
                    reason="initial local fallback site",
                    dry_run=False,
                    verify_http3=False,
                    restart=restart,
                    config=config,
                )
            return report

    def add_candidate(self, candidate: Candidate, *, replace: bool = False) -> MasqConfig:
        config = self.config.copy()
        existing = config.candidate(candidate.id)
        if existing is not None and not replace:
            raise ConfigError(f"candidate {candidate.id!r} already exists")
        config.candidates = [
            item for item in config.candidates if item.id != candidate.id
        ] + [candidate]
        config.candidates.sort(key=lambda item: item.id)
        write_config(self.paths, config)
        self._config = config
        return config

    def remove_candidate(self, candidate_id: str) -> MasqConfig:
        config = self.config.copy()
        if config.candidate(candidate_id) is None:
            raise ConfigError(f"no such candidate: {candidate_id}")
        config.candidates = [
            item for item in config.candidates if item.id != candidate_id
        ]
        write_config(self.paths, config)
        self._config = config
        return config

    def set_candidate_enabled(self, candidate_id: str, enabled: bool) -> MasqConfig:
        config = self.config.copy()
        found = False
        updated: list[Candidate] = []
        for item in config.candidates:
            if item.id == candidate_id:
                found = True
                updated.append(
                    Candidate(
                        id=item.id,
                        url=item.url,
                        enabled=enabled,
                        priority=item.priority,
                        description=item.description,
                    )
                )
            else:
                updated.append(item)
        if not found:
            raise ConfigError(f"no such candidate: {candidate_id}")
        config.candidates = updated
        write_config(self.paths, config)
        self._config = config
        return config

    def set_mode(self, mode: str, *, dry_run: bool = False) -> CycleReport:
        if mode not in {"auto", *EFFECTIVE_MODES}:
            raise ConfigError(
                f"mode {mode!r} is not one of auto, {', '.join(EFFECTIVE_MODES)}"
            )
        with exclusive_lock(self.paths):
            config = self.config.copy()
            config.mode = mode
            problems = config.validate()
            if problems:
                raise ConfigError("; ".join(problems))
            # The in-memory copy is used for planning even in dry-run mode;
            # only a real run writes it to disk.
            self._config = config
            if self._deployer is not None:
                self._deployer.config = config
            if not dry_run:
                write_config(self.paths, config)
            upstream_before = self.deployer.current().get("upstream")
            state = self.load_state()
            plan, _evaluations, probes = self._collect(state)
            deployment: DeploymentResult | None = None
            if not dry_run:
                deployment = self.apply_plan(plan, state, dry_run=dry_run)
            self.save_state(state)
        return CycleReport(
            at=iso(utc_now()) or "",
            configured_mode=mode,
            mode_before=plan.previous_mode,
            upstream_before=upstream_before,
            plan=plan,
            deployment=deployment,
            probes=probes,
            dry_run=dry_run,
            errors=deployment.errors if deployment else [],
        )

