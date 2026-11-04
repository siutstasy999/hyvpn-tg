"""Transactional deployment of a masquerade configuration.

Applying an upstream is treated like any other production change:

1. render the fragment and the complete runtime YAML;
2. validate the result structurally (and with the binary's own ``check`` when
   that build exposes one);
3. back up the files that are about to change;
4. stage the new fragment and move it into place with ``os.replace``;
5. restart the unit — only if the effective configuration really changed;
6. verify the unit and, where the host supports it, an actual HTTP/3 request;
7. roll back automatically when any of that fails.

The HTTP/3 check is only used as a pass/fail signal when the *same* check
succeeded before the change. Some hosts cannot reach their own public UDP/443
(hairpin NAT), and a change must not be rolled back because a diagnostic cannot
run there.
"""

from __future__ import annotations

import inspect
import logging
import os
import shutil
import subprocess
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from core.hysteria_config import atomic_write, chown_if_root, render

from . import site as site_builder
from .capabilities import Capabilities, validate_config_with_binary
from .config import MasqConfig, Paths, load_config
from .render import (
    describe_masquerade,
    extract_masquerade,
    render_fragment,
    validate_runtime_config,
)

log = logging.getLogger(__name__)

MAX_BACKUPS = 20
FRAGMENT_MODE = 0o640


@dataclass(frozen=True)
class Http3Result:
    available: bool
    ok: bool
    status: int | None = None
    detail: str = ""
    command: str = ""

    def to_json(self) -> dict[str, Any]:
        return {
            "available": self.available,
            "ok": self.ok,
            "status": self.status,
            "detail": self.detail,
            "command": self.command,
        }


@dataclass
class DeploymentResult:
    changed: bool = False
    applied: bool = False
    dry_run: bool = False
    mode: str = ""
    upstream: str | None = None
    fragment_path: str = ""
    backup: str | None = None
    restarted: bool = False
    verified: bool = False
    rolled_back: bool = False
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    validation: dict[str, Any] = field(default_factory=dict)
    baseline_http3: Http3Result | None = None
    http3: Http3Result | None = None

    @property
    def ok(self) -> bool:
        return not self.errors and (not self.applied or self.verified or not self.changed)

    def to_json(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "changed": self.changed,
            "applied": self.applied,
            "dry_run": self.dry_run,
            "mode": self.mode,
            "upstream": self.upstream,
            "fragment_path": self.fragment_path,
            "backup": self.backup,
            "restarted": self.restarted,
            "verified": self.verified,
            "rolled_back": self.rolled_back,
            "errors": self.errors,
            "warnings": self.warnings,
            "notes": self.notes,
            "validation": self.validation,
            "baseline_http3": self.baseline_http3.to_json() if self.baseline_http3 else None,
            "http3": self.http3.to_json() if self.http3 else None,
        }


# --------------------------------------------------------------------------- #
# HTTP/3 verification
# --------------------------------------------------------------------------- #

def curl_supports_http3(runner: Callable[..., Any] | None = None) -> tuple[bool, str]:
    """Detect a curl with HTTP/3 (and, when available, ``--http3-only``)."""
    execute = runner or subprocess.run
    try:
        result = execute(
            ["curl", "-V"], capture_output=True, text=True, timeout=10, check=False
        )
    except (OSError, subprocess.SubprocessError):
        return False, "curl is not installed"
    text = f"{result.stdout or ''}{result.stderr or ''}"
    if result.returncode != 0:
        return False, "curl -V failed"
    upper = text.upper()
    if "HTTP3" not in upper and "HTTP/3" not in upper:
        return False, "this curl was built without HTTP/3 support"
    return True, "curl supports HTTP/3"


def _curl_http3_flag(runner: Callable[..., Any] | None = None) -> str:
    execute = runner or subprocess.run
    try:
        result = execute(
            ["curl", "--help", "all"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        if "--http3-only" in f"{result.stdout or ''}{result.stderr or ''}":
            return "--http3-only"
    except (OSError, subprocess.SubprocessError):
        pass
    return "--http3"


def check_http3(
    domain: str,
    port: int = 443,
    *,
    runner: Callable[..., Any] | None = None,
    attempts: int = 2,
    timeout: float = 10.0,
    sleep: Callable[[float], None] = time.sleep,
) -> Http3Result:
    """Fetch the server's own page over HTTP/3 with normal certificate checks."""
    supported, detail = curl_supports_http3(runner)
    if not supported:
        return Http3Result(available=False, ok=False, detail=detail)

    execute = runner or subprocess.run
    flag = _curl_http3_flag(runner)
    command = [
        "curl",
        flag,
        "--silent",
        "--show-error",
        "--output",
        os.devnull,
        "--write-out",
        "%{http_code}",
        "--max-time",
        str(int(timeout)),
        f"https://{domain}:{port}/",
    ]
    last_detail = ""
    status: int | None = None
    for attempt in range(1, attempts + 1):
        try:
            result = execute(
                command, capture_output=True, text=True, timeout=timeout + 5, check=False
            )
        except (OSError, subprocess.SubprocessError) as exc:
            last_detail = f"curl failed: {exc}"
            break
        raw = (result.stdout or "").strip()
        last_detail = (result.stderr or "").strip() or raw
        try:
            status = int(raw) if raw else None
        except ValueError:
            status = None
        if status is not None and 100 <= status < 500:
            return Http3Result(
                available=True,
                ok=200 <= status < 400,
                status=status,
                detail=f"HTTP {status} over HTTP/3",
                command=" ".join(command),
            )
        if attempt < attempts:
            sleep(2)
    return Http3Result(
        available=True,
        ok=False,
        status=status,
        detail=last_detail or "no HTTP status over HTTP/3",
        command=" ".join(command),
    )


# --------------------------------------------------------------------------- #
# deployer
# --------------------------------------------------------------------------- #

class Deployer:
    """Applies masquerade fragments to a running Hysteria2 installation."""

    def __init__(
        self,
        paths: Paths,
        *,
        domain: str,
        config: MasqConfig | None = None,
        capabilities: Capabilities | None = None,
        runner: Callable[..., Any] | None = None,
        http3_checker: Callable[..., Http3Result] | None = None,
        sleep: Callable[[float], None] = time.sleep,
        service_timeout: float = 20.0,
        server_port: int = 443,
    ):
        self.paths = paths
        self.domain = domain
        self.config = config or load_config(paths)
        self.capabilities = capabilities
        self._runner = runner
        self._http3 = http3_checker or check_http3
        self._http3_takes_runner = True
        try:
            parameters = inspect.signature(self._http3).parameters
            self._http3_takes_runner = "runner" in parameters or any(
                parameter.kind is inspect.Parameter.VAR_KEYWORD
                for parameter in parameters.values()
            )
        except (TypeError, ValueError):  # pragma: no cover - builtins
            self._http3_takes_runner = True
        self._sleep = sleep
        self.service_timeout = service_timeout
        self.server_port = server_port

    def http3_check(self) -> Http3Result:
        """Fetch the server's own masquerade page over HTTP/3."""
        if self._http3_takes_runner:
            return self._http3(self.domain, self.server_port, runner=self._runner)
        return self._http3(self.domain, self.server_port)  # type: ignore[call-arg]

    # -- inspection -------------------------------------------------------- #

    def fragment_text(self) -> str:
        try:
            return self.paths.fragment.read_text(encoding="utf-8")
        except OSError:
            return ""

    def current(self) -> dict[str, Any]:
        return describe_masquerade(extract_masquerade(self.fragment_text()))

    def current_mode(self) -> str:
        return str(self.current().get("mode") or "none")

    def current_upstream(self) -> str | None:
        return self.current().get("upstream")

    def runtime_mode(self) -> str:
        try:
            text = self.paths.runtime_config.read_text(encoding="utf-8")
        except OSError:
            return ""
        return str(describe_masquerade(extract_masquerade(text)).get("mode") or "")

    # -- commands ---------------------------------------------------------- #

    def _run(self, args: list[str], timeout: float = 60.0):
        execute = self._runner or subprocess.run
        return execute(
            args, capture_output=True, text=True, timeout=timeout, check=False
        )

    def service_active(self) -> bool:
        try:
            result = self._run(["systemctl", "is-active", self.paths.service], timeout=15)
        except (OSError, subprocess.SubprocessError) as exc:
            log.warning("systemctl is-active failed: %s", exc)
            return False
        state = (result.stdout or "").strip()
        if result.returncode == 0 and state == "active":
            return True
        return False

    def restart_service(self) -> tuple[bool, str]:
        try:
            result = self._run(["systemctl", "restart", self.paths.service])
        except (OSError, subprocess.SubprocessError) as exc:
            return False, f"systemctl restart failed: {exc}"
        if result.returncode != 0:
            detail = (result.stderr or result.stdout or "").strip()
            return False, f"systemctl restart exited {result.returncode}: {detail}"
        deadline = time.monotonic() + self.service_timeout
        while time.monotonic() < deadline:
            if self.service_active():
                return True, "service is active"
            self._sleep(1)
        return False, "service did not become active in time"

    # -- rendering / validation -------------------------------------------- #

    def build_fragment(
        self,
        mode: str,
        *,
        upstream_url: str | None = None,
    ) -> str:
        return render_fragment(
            mode,
            self.config,
            upstream_url=upstream_url,
            site_dir=str(self.paths.site_dir),
            runtime_config=str(self.paths.runtime_config),
        )

    def render_runtime(self, fragment_text: str) -> str:
        try:
            template = self.paths.template.read_text(encoding="utf-8")
        except OSError as exc:
            raise RuntimeError(
                f"cannot read the configuration template {self.paths.template}: {exc}"
            ) from exc
        env = {
            # Placeholders only: validation cares about structure, not secrets,
            # and this keeps the Traffic Stats secret out of staging files.
            "TRAFFIC_STATS_SECRET": "staging-placeholder-not-a-secret",
            "ACME_DOMAIN": self.domain,
            "ACME_EMAIL": f"postmaster@{self.domain}" if self.domain else "postmaster@localhost",
        }
        return render(template, env, fragment_text)

    def validate(
        self,
        mode: str,
        fragment_text: str,
        *,
        check_with_binary: bool = True,
    ) -> tuple[bool, list[str], list[str], list[str]]:
        """Return (ok, errors, warnings, notes)."""
        errors: list[str] = []
        warnings: list[str] = []
        notes: list[str] = []
        try:
            rendered = self.render_runtime(fragment_text)
        except RuntimeError as exc:
            return False, [str(exc)], warnings, notes

        result = validate_runtime_config(
            rendered,
            domain=self.domain,
            expected_mode=mode,
            site_dir=str(self.paths.site_dir),
        )
        errors.extend(result.errors)
        warnings.extend(result.warnings)
        if errors:
            return False, errors, warnings, notes

        if check_with_binary and self.capabilities and self.capabilities.config_check:
            staging = self.paths.state_dir / "staging" / "validate.yaml"
            try:
                atomic_write(staging, rendered, mode=0o600)
                checked, message = validate_config_with_binary(
                    self.capabilities, staging, self._runner
                )
                notes.append(message)
                if checked and message.lower().startswith("config check failed"):
                    errors.append(message)
            finally:
                try:
                    staging.unlink()
                except OSError:
                    pass
        elif check_with_binary and self.capabilities and self.capabilities.present:
            notes.append(
                "the installed hysteria exposes no config check command; the "
                "rendered YAML was validated structurally and the service is "
                "verified after the restart"
            )
        elif check_with_binary:
            notes.append(
                "the hysteria binary was not found; the rendered YAML was "
                "validated structurally"
            )
        return not errors, errors, warnings, notes

    # -- backups ----------------------------------------------------------- #

    def backup(self, *, reason: str = "") -> Path | None:
        if not self.paths.fragment.exists():
            return None
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S-%f")
        self.paths.backups.mkdir(parents=True, exist_ok=True)
        target = self.paths.backups / f"fragment-{stamp}.yaml"
        shutil.copy2(self.paths.fragment, target)
        try:
            os.chmod(target, FRAGMENT_MODE)
        except OSError:  # pragma: no cover
            pass
        meta = self.paths.backups / f"fragment-{stamp}.json"
        atomic_write(
            meta,
            _json_dump(
                {
                    "created_at": datetime.now(timezone.utc).isoformat(),
                    "reason": reason,
                    "mode": self.current_mode(),
                    "upstream": self.current_upstream(),
                }
            ),
            mode=0o640,
        )
        self._rotate_backups()
        return target

    def _rotate_backups(self) -> None:
        try:
            backups = sorted(self.paths.backups.glob("fragment-*.yaml"))
        except OSError:  # pragma: no cover
            return
        for stale in backups[:-MAX_BACKUPS]:
            for path in (stale, stale.with_suffix(".json")):
                try:
                    path.unlink()
                except OSError:
                    pass

    # -- apply ------------------------------------------------------------- #

    def apply(
        self,
        mode: str,
        *,
        upstream_url: str | None = None,
        reason: str = "",
        dry_run: bool = False,
        verify_http3: bool = True,
        restart: bool = True,
        config: MasqConfig | None = None,
    ) -> DeploymentResult:
        if config is not None:
            self.config = config

        result = DeploymentResult(
            dry_run=dry_run,
            mode=mode,
            upstream=upstream_url,
            fragment_path=str(self.paths.fragment),
        )

        if mode == "file" and not dry_run:
            changed = site_builder.materialize(
                self.paths.site_dir, domain=self.domain
            )
            if changed:
                result.notes.append(
                    "fallback site updated: " + ", ".join(changed)
                )
        elif mode == "file":
            result.notes.append("dry-run: the fallback site was not written")

        try:
            desired = self.build_fragment(mode, upstream_url=upstream_url)
        except ValueError as exc:
            result.errors.append(str(exc))
            return result

        current = self.fragment_text()
        if desired.strip() == current.strip():
            result.notes.append(
                "the effective masquerade configuration is already in place; "
                "nothing was written and the service was not restarted"
            )
            return result

        result.changed = True
        ok, errors, warnings, notes = self.validate(mode, desired)
        result.errors.extend(errors)
        result.warnings.extend(warnings)
        result.notes.extend(notes)
        result.validation = {"ok": ok, "errors": errors, "warnings": warnings}
        if not ok:
            result.notes.append("nothing was changed: the proposed configuration failed validation")
            return result

        if dry_run:
            result.notes.append("dry-run: the configuration was validated but not applied")
            return result

        if verify_http3 and restart:
            baseline = self.http3_check()
            result.baseline_http3 = baseline
            if not baseline.ok:
                result.notes.append(
                    "HTTP/3 self-check is not usable on this host before the "
                    f"change ({baseline.detail}); deployment falls back to "
                    "configuration and service verification"
                )

        backup = self.backup(reason=reason or f"{mode}:{upstream_url or ''}")
        result.backup = str(backup) if backup else None

        staging_dir = self.paths.state_dir / "staging"
        staging = staging_dir / "masquerade.fragment.yaml"
        try:
            atomic_write(staging, desired, mode=FRAGMENT_MODE)
            chown_if_root(staging, "hyvpn")
            os.replace(staging, self.paths.fragment)
            chown_if_root(self.paths.fragment, "hyvpn")
        except OSError as exc:
            result.errors.append(f"could not install the fragment: {exc}")
            return result

        # Keep a last known-good copy: the renderer prefers it over a fragment
        # that later turns out to be unreadable.
        try:
            atomic_write(
                self.paths.fragment.with_name(self.paths.fragment.name + ".last-good"),
                desired,
                mode=FRAGMENT_MODE,
            )
        except OSError as exc:  # pragma: no cover - non-fatal
            result.warnings.append(f"could not update the last known-good copy: {exc}")

        result.applied = True
        if not restart:
            result.notes.append(
                "the service restart was skipped: the unit picks the fragment up "
                "when it starts"
            )
            return result
        started, detail = self.restart_service()
        result.restarted = started
        if not started:
            result.errors.append(detail)
            self._rollback(result, backup)
            return result
        result.notes.append(detail)

        verified, verify_errors = self._verify_runtime(mode, upstream_url)
        result.verified = verified
        result.errors.extend(verify_errors)
        if not verified:
            self._rollback(result, backup)
            return result

        if verify_http3 and result.baseline_http3 and result.baseline_http3.ok:
            after = self.http3_check()
            result.http3 = after
            if not after.ok:
                result.errors.append(
                    f"HTTP/3 masquerade check failed after the change: {after.detail}"
                )
                self._rollback(result, backup)
                return result
            result.notes.append(f"HTTP/3 masquerade check: {after.detail}")
        elif verify_http3:
            after = self.http3_check()
            result.http3 = after
            if after.available:
                result.notes.append(
                    "HTTP/3 self-check after the change: "
                    f"{after.detail or 'no status'} (not used as a gate: it did "
                    "not pass before the change either)"
                )
            else:
                result.notes.append(f"HTTP/3 self-check skipped: {after.detail}")

        return result

    def _verify_runtime(
        self, mode: str, upstream_url: str | None
    ) -> tuple[bool, list[str]]:
        errors: list[str] = []
        if not self.service_active():
            errors.append("the service is not active after the restart")
            return False, errors

        try:
            runtime_text = self.paths.runtime_config.read_text(encoding="utf-8")
        except OSError:
            runtime_text = ""

        if runtime_text:
            actual = describe_masquerade(extract_masquerade(runtime_text))
            runtime_mode = actual.get("mode")
            if runtime_mode != mode:
                errors.append(
                    "the running configuration still has masquerade mode "
                    f"{runtime_mode!r} instead of {mode!r}"
                )
            elif mode == "proxy":
                if upstream_url and actual.get("upstream") != upstream_url:
                    errors.append(
                        "the running configuration points at "
                        f"{actual.get('upstream')!r} instead of {upstream_url!r}"
                    )
                if actual.get("insecure"):
                    errors.append(
                        "the running configuration disables upstream certificate "
                        "verification"
                    )
        else:
            errors.append(
                f"the runtime configuration {self.paths.runtime_config} was not "
                "rendered; check `journalctl -u hysteria-server` for the "
                "ExecStartPre output"
            )
        return not errors, errors

    def _rollback(self, result: DeploymentResult, backup: Path | None) -> None:
        result.notes.append("rolling back to the previous configuration")
        try:
            if backup is not None:
                shutil.copy2(backup, self.paths.fragment)
                chown_if_root(self.paths.fragment, "hyvpn")
                try:
                    os.chmod(self.paths.fragment, FRAGMENT_MODE)
                except OSError:  # pragma: no cover
                    pass
            elif self.paths.fragment.exists():
                self.paths.fragment.unlink()
            restored, detail = self.restart_service()
            result.rolled_back = restored
            result.notes.append(f"rollback restart: {detail}")
            if not restored:
                result.errors.append(
                    "rollback restart failed: the service is down and needs "
                    "manual attention (`journalctl -u hysteria-server -n 100`)"
                )
        except OSError as exc:  # pragma: no cover - defensive
            result.errors.append(f"rollback failed: {exc}")


def _json_dump(payload: dict[str, Any]) -> str:
    import json

    return json.dumps(payload, ensure_ascii=False, indent=2) + "\n"
