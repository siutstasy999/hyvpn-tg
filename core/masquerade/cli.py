"""Command implementations for ``hyvpn masquerade``.

The command layer only formats and asks questions; every decision lives in
:mod:`core.masquerade.engine`. Keeping it that way means the CLI, the Telegram
bot and the systemd timer exercise the same logic.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from . import diagnostics, requests
from .config import ConfigError, MasqConfig, Paths, load_config
from .deploy import DeploymentResult
from .diagnostics import DiagnosticReport, openssl_sans
from .engine import InitReport, MasqueradeEngine, Status
from .models import (
    CANDIDATE_ID_RE,
    Candidate,
    Evaluation,
    Thresholds,
    check_upstream_url,
)
from .scoring import rank_key
from .selector import Plan

EXIT_OK = 0
EXIT_FAIL = 1
EXIT_USAGE = 2


@dataclass
class Context:
    """Everything a command needs, injected so tests need no real server."""

    paths: Paths
    domain: str
    server_port: int = 443
    acme_dir: str = "/var/lib/hysteria/acme"
    cert_status_path: str = "/var/lib/hyvpn/cert.json"
    json_output: bool = False
    assume_yes: bool = False
    interactive: bool = True
    out: Callable[[str], None] = field(default=print)
    err: Callable[[str], None] = field(default=lambda text: print(text, file=sys.stderr))
    runner: Callable[..., Any] | None = None
    sleep: Callable[[float], None] | None = None

    def engine(self, *, config: MasqConfig | None = None) -> MasqueradeEngine:
        kwargs: dict[str, Any] = {}
        if self.runner is not None:
            kwargs["runner"] = self.runner
        if self.sleep is not None:
            kwargs["sleep"] = self.sleep
        return MasqueradeEngine(
            self.paths,
            domain=self.domain,
            server_port=self.server_port,
            acme_dir=self.acme_dir,
            cert_status_path=self.cert_status_path,
            config=config,
            **kwargs,
        )

    # -- output helpers ---------------------------------------------------- #

    def emit(self, payload: dict[str, Any]) -> None:
        self.out(json.dumps(payload, ensure_ascii=False, indent=2))

    def require_root(self, action: str) -> bool:
        geteuid = getattr(os, "geteuid", None)
        if geteuid is None:
            return True
        if geteuid() != 0:
            self.err(
                f"{action} changes the production configuration and must run as "
                "root: use `sudo hyvpn masquerade ...`"
            )
            return False
        return True

    def approve(self, question: str) -> bool:
        if self.assume_yes:
            return True
        if not self.interactive:
            self.err(
                "refusing to change the production configuration without "
                "confirmation: re-run with --yes in a non-interactive session"
            )
            return False
        self.out(question)
        try:
            answer = input("Apply? [y/N] ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            self.err("aborted")
            return False
        return answer in {"y", "yes", "да", "д"}


# --------------------------------------------------------------------------- #
# formatting
# --------------------------------------------------------------------------- #

def _row(label: str, value: Any, width: int = 20) -> str:
    return f"  {label:<{width}}{value}"


def format_status(status: Status, *, sans: list[str], cert_covers: bool) -> str:
    lines = [
        "Masquerade",
        _row("configured mode", status.configured_mode),
        _row("effective mode", status.effective_mode),
        _row("upstream", status.upstream or "-"),
        _row("candidate", status.candidate_id or "-"),
        _row("candidate health", status.candidate_health),
        _row(
            "last probe",
            f"{status.last_probe or 'never'}"
            + (f" ({status.last_latency_ms:.0f} ms)" if status.last_latency_ms else ""),
        ),
        _row("service", "active" if status.service_active else "not active"),
        _row(
            "runtime config",
            (
                f"{status.runtime_mode}"
                + ("" if status.runtime_mode == status.effective_mode else " (out of sync)")
            )
            if status.runtime_mode
            else "not rendered yet",
        ),
        _row(
            "hysteria",
            f"{status.capabilities.version or 'not installed'} "
            f"({status.capabilities.binary})",
        ),
        "",
        "TLS (independent of masquerade)",
        _row("domain", status.certificate.domain if status.certificate else "-"),
        _row("SANs", ", ".join(sans) or "-"),
        _row("covers domain", "yes" if cert_covers else "no"),
    ]
    cert = status.certificate
    if cert is None:
        lines.append(_row("certificate", "unknown"))
    elif not cert.known:
        lines.append(_row("certificate", f"not available ({cert.error})"))
    else:
        lines.append(_row("expires", f"{cert.not_after} ({cert.days_left} days left)"))
        lines.append(_row("issuer", cert.issuer or "-"))

    lines += [
        "",
        "Fallback site",
        _row("directory", status.site_dir),
        _row("ready", "yes" if status.fallback_ready else "no (run `hyvpn masquerade init`)"),
        "",
        "Candidates",
    ]
    if not status.evaluations:
        lines.append("  (none configured — the local fallback site is served)")
    else:
        for evaluation in status.evaluations:
            lines.append("  " + format_evaluation(evaluation))
    if status.pending_switch:
        lines.append(
            f"  pending switch: {status.pending_switch.get('id')} "
            f"({status.pending_switch.get('count')} confirmation cycle(s))"
        )
    if status.last_error:
        lines.append(f"  last error: {status.last_error}")
    return "\n".join(lines)


def format_evaluation(evaluation: Evaluation) -> str:
    icon = {"healthy": "✅", "degraded": "⚠️", "unhealthy": "🔴"}.get(
        evaluation.health, "⚪️"
    )
    return (
        f"{icon} {evaluation.candidate_id:<16} {evaluation.health:<9} "
        f"score {evaluation.score:.2f}  "
        f"{evaluation.mean_latency_ms:.0f} ms  "
        f"{evaluation.samples} sample(s)  {evaluation.url}"
    )


def format_plan(plan: Plan, thresholds: Thresholds) -> str:
    lines = [
        "Proposed configuration",
        _row("mode", f"{plan.previous_mode} -> {plan.mode}"),
        _row("upstream", f"{plan.previous_candidate or '-'} -> {plan.candidate_id or '-'}"),
        _row("URL", plan.upstream or "-"),
        _row("changes", "yes" if plan.changed else "no — nothing to apply"),
        _row("thresholds", (
            f"min score {thresholds.min_score:.2f}, "
            f"switch margin {thresholds.switch_margin:.2f} x "
            f"{thresholds.switch_confirmations} cycles, "
            f"failover after {thresholds.failover_after_failures} failed cycle(s)"
        )),
        _row("reason", plan.reason),
    ]
    if plan.blocked:
        lines.insert(1, "  ⚠️ blocked: the current configuration would be kept")
    if plan.changes:
        lines += ["", "Changes"] + [f"  - {change}" for change in plan.changes]
    if plan.evaluations:
        lines += ["", "Candidates"]
        for evaluation in sorted(
            plan.evaluations, key=lambda item: rank_key(item, 0)
        ):
            lines.append(
                "  "
                + format_evaluation(evaluation)
                + (f"  [{'; '.join(evaluation.reasons)}]" if evaluation.reasons else "")
            )
    return "\n".join(lines)


def format_deployment(result: DeploymentResult) -> str:
    lines = ["Deployment"]
    if not result.changed:
        lines.append(_row("result", "no change"))
    elif not result.applied:
        lines.append(_row("result", "not applied"))
    elif result.rolled_back:
        lines.append(_row("result", "FAILED — rolled back"))
    elif result.verified:
        lines.append(_row("result", "applied and verified"))
    else:
        lines.append(_row("result", "applied, not verified"))
    lines.append(_row("mode", f"{result.mode} ({result.upstream or '-'})"))
    if result.backup:
        lines.append(_row("backup", result.backup))
    if result.http3:
        lines.append(_row("HTTP/3", result.http3.detail or "-"))
    for warning in result.warnings:
        lines.append(_row("warning", warning))
    for error in result.errors:
        lines.append(_row("error", error))
    for note in result.notes:
        lines.append(_row("note", note))
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# shared helpers
# --------------------------------------------------------------------------- #

def _certificate_details(ctx: Context) -> tuple[list[str], bool]:
    from core.cert_service import find_cert_file

    path = find_cert_file(ctx.domain, ctx.acme_dir) if ctx.domain else None
    if path is None:
        return [], False
    sans = openssl_sans(path)
    covers = bool(ctx.domain) and (ctx.domain in sans or f"*.{ctx.domain}" in sans)
    return sans, covers


def _load_config(ctx: Context) -> MasqConfig | None:
    try:
        return load_config(ctx.paths)
    except ConfigError as exc:
        ctx.err(f"masquerade.json is not usable: {exc}")
        return None


def _rebuild_engine_config(ctx: Context) -> MasqueradeEngine:
    engine = ctx.engine()
    engine.ensure_config()
    engine.reload_config()
    return engine


# --------------------------------------------------------------------------- #
# commands
# --------------------------------------------------------------------------- #

def cmd_status(ctx: Context) -> int:
    engine = ctx.engine()
    try:
        status = engine.status()
    except ConfigError as exc:
        ctx.err(f"masquerade.json is not usable: {exc}")
        return EXIT_FAIL
    sans, covers = _certificate_details(ctx)
    if ctx.json_output:
        payload = status.to_json()
        payload["certificate_sans"] = sans
        payload["certificate_covers_domain"] = covers
        ctx.emit(payload)
        return EXIT_OK
    ctx.out(format_status(status, sans=sans, cert_covers=covers))
    return EXIT_OK


def cmd_check(ctx: Context) -> int:
    engine = ctx.engine()
    try:
        report = engine.check()
    except ConfigError as exc:
        ctx.err(f"masquerade.json is not usable: {exc}")
        return EXIT_FAIL
    if ctx.json_output:
        ctx.emit(report)
    else:
        lines = ["Masquerade check", _row("result", "ok" if report["ok"] else "problems found")]
        for problem in report.get("problems", []):
            lines.append(_row("problem", problem))
        for warning in report.get("warnings", []):
            lines.append(_row("warning", warning))
        for note in report.get("notes", []):
            lines.append(_row("note", note))
        ctx.out("\n".join(lines))
    return EXIT_OK if report["ok"] else EXIT_FAIL


def cmd_doctor(ctx: Context) -> int:
    report: DiagnosticReport = diagnostics.collect(
        ctx.paths,
        domain=ctx.domain,
        server_port=ctx.server_port,
        acme_dir=ctx.acme_dir,
        runner=ctx.runner,
    )
    if ctx.json_output:
        ctx.emit(report.to_json())
        return EXIT_OK if report.ok else EXIT_FAIL
    ctx.out(format_diagnostic(report))
    return EXIT_OK if report.ok else EXIT_FAIL


def format_diagnostic(report: DiagnosticReport) -> str:
    sections = report.sections
    system = sections.get("system", {})
    hysteria = sections.get("hysteria", {})
    service = sections.get("service", {})
    certificate = sections.get("certificate", {})
    masquerade = sections.get("masquerade", {})
    ports = sections.get("ports", {})
    lines = [
        "Environment",
        _row("distribution", system.get("distribution", "-")),
        _row("kernel", system.get("kernel", "-")),
        _row("architecture", system.get("architecture", "-")),
        _row("python", system.get("python", "-")),
        "",
        "Hysteria2",
        _row("binary", hysteria.get("binary", "-")),
        _row("version", hysteria.get("version", "-")),
        _row("masquerade", "supported" if hysteria.get("supports_masquerade") else "NOT supported"),
        _row("config check", ", ".join(hysteria.get("config_check") or []) or "not available"),
        "",
        "Service",
        _row("unit", service.get("service", "-")),
        _row("state", service.get("ActiveState", "unknown")),
        _row("user", service.get("User", "-")),
        _row("fragment", service.get("FragmentPath", "-")),
        "",
        "Paths",
    ]
    for name, info in (sections.get("paths") or {}).items():
        if not isinstance(info, dict):  # pragma: no cover - defensive
            continue
        if info.get("exists"):
            lines.append(
                _row(
                    name,
                    f"{info.get('path')}  {info.get('mode')} "
                    f"{info.get('owner')}:{info.get('group')}",
                )
            )
        else:
            lines.append(_row(name, f"{info.get('path')}  (missing)"))
    lines += ["", "TLS certificate"]
    if certificate.get("found"):
        lines += [
            _row("path", certificate.get("path", "-")),
            _row("SANs", ", ".join(certificate.get("sans") or []) or "-"),
            _row("covers domain", "yes" if certificate.get("covers_domain") else "NO"),
        ]
    else:
        lines.append(_row("state", certificate.get("note", "not found")))
    lines += ["", "Masquerade"]
    lines += [
        _row("mode", masquerade.get("mode", "none")),
        _row("upstream", masquerade.get("upstream") or "-"),
        _row("source", masquerade.get("source") or "-"),
    ]
    lines += ["", f"Listening on port {ports.get('port')}"]
    for kind in ("tcp", "udp"):
        for entry in ports.get(kind) or []:
            lines.append(_row(kind, f"{entry.get('local')}  {entry.get('process', '')}".strip()))
    if not ports.get("tcp") and not ports.get("udp"):
        lines.append(_row("", f"nothing on port {ports.get('port')}"))
    for warning in report.warnings:
        lines.append(_row("warning", warning))
    for error in report.errors:
        lines.append(_row("error", error))
    return "\n".join(lines)


def cmd_candidates_list(ctx: Context) -> int:
    engine = ctx.engine()
    try:
        config = engine.config
        status = engine.status()
    except ConfigError as exc:
        ctx.err(f"masquerade.json is not usable: {exc}")
        return EXIT_FAIL
    evaluations = {item.candidate_id: item for item in status.evaluations}
    if ctx.json_output:
        ctx.emit(
            {
                "mode": config.mode,
                "candidates": [
                    {
                        **candidate.to_json(),
                        "health": evaluations[candidate.id].to_json()
                        if candidate.id in evaluations
                        else None,
                    }
                    for candidate in config.candidates
                ],
            }
        )
        return EXIT_OK
    if not config.candidates:
        ctx.out(
            "No candidates configured.\n"
            "Add an administrator-authorised upstream, for example:\n"
            "  hyvpn masquerade candidates add https://vpn.example.com/ --id own-site"
        )
        return EXIT_OK
    lines = [f"Candidates ({len(config.candidates)})"]
    for candidate in config.candidates:
        evaluation = evaluations.get(candidate.id)
        enabled = "enabled " if candidate.enabled else "disabled"
        prefix = f"  [{enabled}] {candidate.id:<16} {candidate.url}"
        if candidate.description:
            prefix += f"  — {candidate.description}"
        lines.append(prefix)
        if evaluation is None:
            lines.append("      never probed")
        else:
            lines.append(
                f"      {evaluation.health}, score {evaluation.score:.2f}, "
                f"{evaluation.mean_latency_ms:.0f} ms, "
                f"{evaluation.successes}/{evaluation.samples} successful, "
                f"last success {evaluation.last_success or '-'}"
            )
            if evaluation.reasons:
                lines.append(f"      {'; '.join(evaluation.reasons)}")
    lines.append(f"\npriority is used as a tie-breaker; registry: {ctx.paths.config}")
    ctx.out("\n".join(lines))
    return EXIT_OK


def cmd_candidates_test(ctx: Context) -> int:
    engine = ctx.engine()
    try:
        config = engine.config
    except ConfigError as exc:
        ctx.err(f"masquerade.json is not usable: {exc}")
        return EXIT_FAIL
    if not config.enabled_candidates():
        ctx.out("No enabled candidates to test.")
        return EXIT_OK
    state = engine.load_state()
    probes = engine.probe_all(state)
    evaluations = engine.evaluate(state)
    engine.save_state(state)
    failures = 0
    if ctx.json_output:
        ctx.emit(
            {
                "probes": {
                    candidate_id: [probe.to_json() for probe in items]
                    for candidate_id, items in probes.items()
                },
                "evaluations": [item.to_json() for item in evaluations.values()],
            }
        )
    else:
        lines = ["Candidate probes"]
        for candidate in config.enabled_candidates():
            items = probes.get(candidate.id, [])
            last = items[-1] if items else None
            evaluation = evaluations.get(candidate.id)
            lines.append(f"  {candidate.id}  {candidate.url}")
            if last is None:
                lines.append("    not probed")
                failures += 1
                continue
            if last.ok:
                lines.append(
                    f"    HTTP {last.status} {last.content_type} "
                    f"{last.body_bytes} B in {last.total_ms:.0f} ms "
                    f"(dns {last.dns_ms:.0f}, tcp {last.connect_ms:.0f}, "
                    f"tls {last.tls_ms:.0f}, ttfb {last.ttfb_ms:.0f})"
                )
            else:
                failures += 1
                lines.append(
                    f"    FAILED [{last.error_kind or 'probe'}] {last.error}"
                )
            if len(items) > 1:
                lines.append(f"    attempts: {len(items)}")
            if last.redirects:
                lines.append(f"    redirects: {' -> '.join(last.redirects)}")
            if evaluation is not None:
                lines.append(
                    f"    {evaluation.health}, score {evaluation.score:.2f}"
                    + (f" ({'; '.join(evaluation.reasons)})" if evaluation.reasons else "")
                )
        ctx.out("\n".join(lines))
    return EXIT_OK if failures == 0 else EXIT_FAIL


def cmd_candidates_add(ctx: Context, args) -> int:
    url = (args.url or "").strip()
    check = check_upstream_url(url)
    if not check.ok:
        ctx.err(f"invalid upstream URL: {check.error}")
        return EXIT_USAGE
    candidate_id = (args.id or "").strip()
    if not candidate_id:
        candidate_id = check.host.replace(".", "-")[:63]
    if not CANDIDATE_ID_RE.match(candidate_id):
        ctx.err(
            f"invalid candidate id {candidate_id!r}: use lowercase letters, "
            "digits, dot, dash or underscore"
        )
        return EXIT_USAGE
    if not ctx.require_root("adding a candidate"):
        return EXIT_FAIL
    engine = _rebuild_engine_config(ctx)
    candidate = Candidate(
        id=candidate_id,
        url=url,
        enabled=True,
        priority=int(args.priority or 0),
        description=(args.description or "").strip(),
    )
    try:
        engine.add_candidate(candidate, replace=bool(args.replace))
    except ConfigError as exc:
        ctx.err(str(exc))
        return EXIT_FAIL
    ctx.out(f"candidate added: {candidate.id} -> {candidate.url}")
    ctx.out("run `hyvpn masquerade candidates test` and `hyvpn masquerade optimize --apply` next")
    return EXIT_OK


def cmd_candidates_remove(ctx: Context, args) -> int:
    if not ctx.require_root("removing a candidate"):
        return EXIT_FAIL
    engine = ctx.engine()
    try:
        engine.remove_candidate(args.id)
    except ConfigError as exc:
        ctx.err(str(exc))
        return EXIT_FAIL
    ctx.out(f"candidate removed: {args.id}")
    return EXIT_OK


def cmd_candidates_enable(ctx: Context, args, enabled: bool) -> int:
    if not ctx.require_root("changing a candidate"):
        return EXIT_FAIL
    engine = ctx.engine()
    try:
        engine.set_candidate_enabled(args.id, enabled)
    except ConfigError as exc:
        ctx.err(str(exc))
        return EXIT_FAIL
    ctx.out(f"candidate {'enabled' if enabled else 'disabled'}: {args.id}")
    return EXIT_OK


def cmd_optimize(ctx: Context, args) -> int:
    dry_run = bool(args.dry_run) or not bool(args.apply)
    if not dry_run and not ctx.require_root("applying a masquerade configuration"):
        return EXIT_FAIL
    engine = ctx.engine()
    try:
        plan, _evaluations, state = engine.plan(record_decision_state=not dry_run)
    except ConfigError as exc:
        ctx.err(f"masquerade.json is not usable: {exc}")
        return EXIT_FAIL

    if ctx.json_output and dry_run:
        ctx.emit(plan.to_json())
        return EXIT_OK if not plan.blocked else EXIT_FAIL
    if not ctx.json_output:
        ctx.out(format_plan(plan, engine.config.thresholds))

    if dry_run:
        ctx.out("\ndry-run: no configuration was changed")
        return EXIT_OK if not plan.blocked else EXIT_FAIL

    if plan.blocked:
        ctx.err("the selection is blocked; nothing was applied")
        return EXIT_FAIL
    if not plan.changed:
        ctx.out("\nnothing to apply")
        engine.save_state(state)
        return EXIT_OK
    if not ctx.approve("This will restart hysteria-server.service."):
        ctx.out("aborted: no changes were made")
        return EXIT_FAIL

    result = engine.apply_plan(plan, state, dry_run=False)
    engine.save_state(state)
    if ctx.json_output:
        ctx.emit(result.to_json())
    else:
        ctx.out("\n" + format_deployment(result))
    return EXIT_OK if result.ok and not result.rolled_back else EXIT_FAIL


def cmd_set_mode(ctx: Context, args) -> int:
    if not ctx.require_root("changing the masquerade mode"):
        return EXIT_FAIL
    dry_run = bool(args.dry_run)
    mode = args.mode
    if not dry_run and not ctx.approve(
        f"Set the masquerade mode to {mode} and apply it now?"
    ):
        ctx.out("aborted: no changes were made")
        return EXIT_FAIL
    engine = ctx.engine()
    try:
        report = engine.set_mode(mode, dry_run=dry_run)
    except ConfigError as exc:
        ctx.err(str(exc))
        return EXIT_FAIL
    if ctx.json_output:
        ctx.emit(report.to_json())
        return EXIT_OK
    ctx.out(format_plan(report.plan, engine.config.thresholds))
    if report.deployment is not None:
        ctx.out("\n" + format_deployment(report.deployment))
    if dry_run:
        ctx.out("\ndry-run: nothing was applied")
        return EXIT_OK
    deployment = report.deployment
    return EXIT_OK if deployment is not None and deployment.ok else EXIT_FAIL


def format_init(report: InitReport) -> str:
    lines = [
        "Masquerade initialisation",
        _row(
            "configuration",
            f"{report.config_path} "
            f"({'created' if report.config_created else 'kept'})",
        ),
        _row("site directory", report.site_dir),
        _row(
            "fallback site",
            ", ".join(report.site_files_written)
            if report.site_files_written
            else "already up to date",
        ),
        _row("mode before", report.existing_mode),
    ]
    if report.deployment is not None:
        lines += ["", format_deployment(report.deployment)]
    return "\n".join(lines)


def cmd_init(ctx: Context, args: argparse.Namespace | None = None) -> int:
    if not ctx.require_root("initialising masquerade"):
        return EXIT_FAIL
    engine = ctx.engine()
    try:
        restart = not bool(getattr(args, "no_restart", False))
        report = engine.init(restart=restart)
    except ConfigError as exc:
        ctx.err(str(exc))
        return EXIT_FAIL
    if ctx.json_output:
        ctx.emit(report.to_json())
    else:
        ctx.out(format_init(report))
    deployment = report.deployment
    if deployment is not None and (deployment.errors or deployment.rolled_back):
        return EXIT_FAIL
    return EXIT_OK


def cmd_upgrade(ctx: Context, args) -> int:
    """The one command an administrator runs on the server."""
    read_only = bool(getattr(args, "read_only", False))
    dry_run = bool(getattr(args, "dry_run", False)) or read_only

    report = diagnostics.collect(
        ctx.paths,
        domain=ctx.domain,
        server_port=ctx.server_port,
        acme_dir=ctx.acme_dir,
        runner=ctx.runner,
    )
    if ctx.json_output:
        ctx.emit({"diagnostics": report.to_json()})
    else:
        ctx.out(format_diagnostic(report))
        ctx.out("")
    if report.errors:
        ctx.err(
            "the environment does not allow a masquerade upgrade; fix the errors "
            "above first"
        )
        return EXIT_FAIL
    if read_only:
        ctx.out("read-only: no configuration was changed")
        return EXIT_OK

    engine = ctx.engine()
    try:
        config, created = engine.ensure_config()
        engine.reload_config()
        site_changes = engine.ensure_site()
    except (ConfigError, OSError) as exc:
        ctx.err(f"could not prepare the configuration: {exc}")
        return EXIT_FAIL
    if ctx.json_output:
        ctx.out(json.dumps({"config_created": created, "site_files": site_changes}))
    else:
        ctx.out(
            f"configuration: {ctx.paths.config} "
            f"({'created' if created else 'kept'})"
        )
        ctx.out(
            "fallback site: "
            + (", ".join(site_changes) if site_changes else "already up to date")
        )

    plan, _evaluations, state = engine.plan(record_decision_state=not dry_run)
    if not ctx.json_output:
        ctx.out("\n" + format_plan(plan, config.thresholds))

    if dry_run:
        ctx.out("\ndry-run: the configuration was not changed")
        return EXIT_OK if not plan.blocked else EXIT_FAIL
    if plan.blocked:
        ctx.err("the selection is blocked; nothing was applied")
        return EXIT_FAIL
    if not plan.changed:
        ctx.out("\nnothing to change: the running configuration already matches")
        engine.save_state(state)
        return EXIT_OK
    if not ctx.approve(
        "This will write the masquerade fragment and restart "
        "hysteria-server.service."
    ):
        ctx.out("aborted: no changes were made")
        return EXIT_FAIL

    result = engine.apply_plan(plan, state, dry_run=False)
    engine.save_state(state)
    if ctx.json_output:
        ctx.emit(result.to_json())
    else:
        ctx.out("\n" + format_deployment(result))
    if not result.ok or result.rolled_back:
        return EXIT_FAIL
    ctx.out(
        "\nNext steps:\n"
        "  hyvpn masquerade status        what is running now\n"
        "  hyvpn masquerade check         full diagnostics\n"
        f"  add upstreams in {ctx.paths.config}"
    )
    return EXIT_OK


# --------------------------------------------------------------------------- #
# request processing (root worker)
# --------------------------------------------------------------------------- #

def cmd_apply_requests(ctx: Context, *, limit: int = 5) -> int:
    """Process queued bot requests. Runs as root from hy-masqapply.service."""
    if not ctx.require_root("processing apply requests"):
        return EXIT_FAIL
    pending = requests.load_pending(ctx.paths)[:limit]
    if not pending:
        ctx.out("no pending requests")
        return EXIT_OK
    failures = 0
    for request in pending:
        result = _execute_request(ctx, request)
        requests.write_result(ctx.paths, request, result)
        requests.discard(request)
        if not result.get("ok"):
            failures += 1
    ctx.out(f"processed {len(pending)} request(s), {failures} failed")
    return EXIT_OK if failures == 0 else EXIT_FAIL


def _execute_request(ctx: Context, request) -> dict[str, Any]:
    engine = ctx.engine()
    try:
        if request.kind == "set-mode":
            mode = str(request.payload.get("mode", ""))
            report = engine.set_mode(mode)
            applied_ok = bool(report.deployment and report.deployment.ok)
            return {
                "ok": applied_ok and not report.plan.blocked,
                "action": "set-mode",
                "mode": report.plan.mode,
                "deployment": report.deployment.to_json() if report.deployment else None,
            }
        if request.kind in {"optimize", "check", "test-candidates"}:
            if request.kind == "check":
                report = engine.check()
                return {"ok": bool(report.get("ok")), "action": "check", "report": report}
            if request.kind == "test-candidates":
                state = engine.load_state()
                probes = engine.probe_all(state)
                evaluations = engine.evaluate(state)
                engine.save_state(state)
                return {
                    "ok": True,
                    "action": "test-candidates",
                    "evaluations": [item.to_json() for item in evaluations.values()],
                    "probes": {
                        candidate_id: [probe.to_json() for probe in items]
                        for candidate_id, items in probes.items()
                    },
                }
            plan, _evaluations, state = engine.plan()
            if plan.blocked:
                return {
                    "ok": False,
                    "action": "optimize",
                    "plan": plan.to_json(),
                    "error": plan.reason,
                }
            result = engine.apply_plan(plan, state, dry_run=False)
            engine.save_state(state)
            return {
                "ok": bool(result.ok and not result.rolled_back),
                "action": "optimize",
                "plan": plan.to_json(),
                "deployment": result.to_json(),
            }
    except ConfigError as exc:
        return {"ok": False, "action": request.kind, "error": str(exc)}
    except Exception as exc:  # noqa: BLE001 - the worker must report, not crash
        return {"ok": False, "action": request.kind, "error": f"{type(exc).__name__}: {exc}"}
    return {"ok": False, "action": request.kind, "error": "unsupported request"}


def last_results(ctx: Context, limit: int = 3) -> list[dict[str, Any]]:
    return requests.read_results(ctx.paths, limit=limit)
