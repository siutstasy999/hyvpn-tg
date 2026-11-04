"""Shared fakes for the masquerade tests.

No test in this directory touches the network, a real systemd or a real
Hysteria2 installation: every collaborator that would do I/O is injected.
"""

from __future__ import annotations

import subprocess
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from core.masquerade.capabilities import Capabilities
from core.masquerade.config import MasqConfig, Paths
from core.masquerade.deploy import DeploymentResult, Http3Result
from core.masquerade.engine import Status
from core.masquerade.models import (
    Candidate,
    Evaluation,
    ProbeResult,
    Thresholds,
)
from core.masquerade.probe import ProbeError, RawResponse

TEMPLATE = """# test template
listen: :443

acme:
  domains:
    - ${ACME_DOMAIN}
  email: ${ACME_EMAIL}
  dir: /var/lib/hysteria/acme

auth:
  type: http
  http:
    url: http://127.0.0.1:8080/auth
    insecure: false

trafficStats:
  listen: 127.0.0.1:9999
  secret: ${TRAFFIC_STATS_SECRET}

${MASQUERADE_YAML}
"""


def make_paths(tmp: Path) -> Paths:
    return Paths(
        config=tmp / "etc" / "masquerade.json",
        state_dir=tmp / "state",
        site_dir=tmp / "site",
        fragment=tmp / "etc" / "masquerade.fragment.yaml",
        runtime_config=tmp / "run" / "hysteria-server.yaml",
        template=tmp / "etc" / "template.yaml",
        backups=tmp / "state" / "backups",
        hysteria_binary=tmp / "bin" / "hysteria",
        service="hysteria-server.service",
    )


def seed_template(paths: Paths) -> str:
    paths.template.parent.mkdir(parents=True, exist_ok=True)
    paths.template.write_text(TEMPLATE, encoding="utf-8")
    return TEMPLATE


def html_response(
    status: int = 200,
    *,
    body: bytes | None = None,
    content_type: str = "text/html; charset=utf-8",
    headers: dict[str, str] | None = None,
    connect_ms: float = 12.0,
    tls_ms: float = 20.0,
    ttfb_ms: float = 30.0,
) -> RawResponse:
    payload = body if body is not None else b"<html><body>" + b"x" * 600 + b"</body></html>"
    merged = {"content-type": content_type}
    if headers:
        merged.update({key.lower(): value for key, value in headers.items()})
    return RawResponse(
        status=status,
        headers=merged,
        body=payload,
        connect_ms=connect_ms,
        tls_ms=tls_ms,
        ttfb_ms=ttfb_ms,
    )


class Resolver:
    """Resolver fake: maps host -> addresses or raises."""

    def __init__(self, mapping: dict[str, Any]):
        self.mapping = mapping
        self.calls: list[tuple[str, int]] = []

    def __call__(self, host: str, port: int) -> list[str]:
        self.calls.append((host, port))
        value = self.mapping.get(host)
        if isinstance(value, Exception):
            raise value
        if value is None:
            raise OSError(f"no entry for {host}")
        return list(value)


class Fetcher:
    """Fetcher fake: per-URL list of results (RawResponse or exception)."""

    def __init__(self, mapping: dict[str, Any]):
        self.mapping = mapping
        self.calls: list[dict[str, Any]] = []

    def __call__(
        self,
        host: str,
        port: int,
        path: str,
        addresses: list[str],
        *,
        timeout: float,
        max_body: int,
    ) -> RawResponse:
        self.calls.append(
            {
                "host": host,
                "port": port,
                "path": path,
                "addresses": list(addresses),
                "timeout": timeout,
                "max_body": max_body,
            }
        )
        url = f"https://{host}:{port}{path}" if port != 443 else f"https://{host}{path}"
        value = self.mapping.get(url)
        if value is None:
            value = self.mapping.get(host)
        if value is None:
            raise ProbeError("connect", f"unexpected request to {url}")
        if isinstance(value, Exception):
            raise value
        if isinstance(value, list):
            return value.pop(0) if len(value) > 1 else value[0]
        return value


def probe_result(
    candidate_id: str = "a",
    *,
    ok: bool = True,
    status: int | None = 200,
    total_ms: float = 200.0,
    error_kind: str = "",
    redirects: tuple[str, ...] = (),
    checked_at: datetime | None = None,
) -> ProbeResult:
    return ProbeResult(
        candidate_id=candidate_id,
        url=f"https://{candidate_id}.example/",
        ok=ok,
        status=status,
        error="boom" if not ok else "",
        error_kind=error_kind,
        total_ms=total_ms,
        dns_ms=5.0,
        connect_ms=10.0,
        tls_ms=15.0,
        ttfb_ms=25.0,
        redirects=redirects,
        content_type="text/html",
        body_bytes=600,
        content_ok=ok,
        checked_at=checked_at or datetime.now(timezone.utc),
    )


def evaluation(
    candidate_id: str = "a",
    *,
    score: float = 0.9,
    eligible: bool = True,
    retain_ok: bool = True,
    latest_ok: bool = True,
    health: str = "healthy",
    availability: float = 1.0,
    samples: int = 5,
    consecutive_failures: int = 0,
    reasons: tuple[str, ...] = (),
) -> Evaluation:
    return Evaluation(
        candidate_id=candidate_id,
        url=f"https://{candidate_id}.example/",
        score=score,
        eligible=eligible,
        health=health,
        availability=availability,
        samples=samples,
        successes=int(samples * availability),
        mean_latency_ms=150.0,
        latency_stdev_ms=10.0,
        redirect_chains=0,
        consecutive_failures=consecutive_failures,
        last_success=None,
        last_failure=None,
        reasons=reasons,
        latest_ok=latest_ok,
        retain_ok=retain_ok,
        confident=samples >= 3,
    )


def candidate(candidate_id: str, *, enabled: bool = True, priority: int = 0) -> Candidate:
    return Candidate(
        id=candidate_id,
        url=f"https://{candidate_id}.example/",
        enabled=enabled,
        priority=priority,
    )


def config(
    *candidates: Candidate,
    mode: str = "auto",
    thresholds: Thresholds | None = None,
) -> MasqConfig:
    return MasqConfig(
        mode=mode,
        candidates=list(candidates),
        thresholds=thresholds or Thresholds(),
    )


def capabilities(**overrides: Any) -> Capabilities:
    payload = {
        "binary": "/usr/local/bin/hysteria",
        "present": True,
        "version": "2.6.0",
        "version_tuple": (2, 6, 0, ""),
        "config_check": None,
        "features": {},
        "notes": [],
        "error": "",
    }
    payload.update(overrides)
    return Capabilities(**payload)


class CommandRunner:
    """Fake subprocess.run for systemctl/curl/hysteria invocations."""

    def __init__(self, responses: dict[str, subprocess.CompletedProcess] | None = None):
        self.responses = responses or {}
        self.calls: list[list[str]] = []

    def __call__(self, args, **kwargs):
        self.calls.append(list(args))
        key = " ".join(args)
        for pattern, response in self.responses.items():
            if pattern in key:
                return response
        if args and args[0] == "systemctl" and "is-active" in args:
            return ok("active")
        return ok("")

    def count(self, needle: str) -> int:
        return sum(1 for call in self.calls if needle in " ".join(call))


def ok(stdout: str = "", code: int = 0) -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess([], code, stdout=stdout, stderr="")


def failed(stderr: str = "boom", code: int = 1) -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess([], code, stdout="", stderr=stderr)


@dataclass
class FakeDeployer:
    """Stands in for Deployer when testing the engine only."""

    paths: Paths
    domain: str
    config: MasqConfig | None = None
    mode: str = "none"
    upstream: str | None = None
    runtime: str = ""
    active: bool = True
    applied: bool = True
    http3: Http3Result | None = None
    apply_calls: list[dict[str, Any]] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self.apply_calls is None:
            self.apply_calls = []

    # -- inspection -------------------------------------------------------- #
    def fragment_text(self) -> str:
        try:
            return self.paths.fragment.read_text(encoding="utf-8")
        except OSError:
            return ""

    def current(self) -> dict[str, Any]:
        return {"mode": self.mode, "upstream": self.upstream}

    def current_mode(self) -> str:
        return self.mode

    def runtime_mode(self) -> str:
        return self.runtime or self.mode

    def service_active(self) -> bool:
        return self.active

    def validate(self, mode: str, fragment_text: str, *, check_with_binary: bool = True):
        return True, [], [], []

    def http3_check(self) -> Http3Result | None:
        return self.http3

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
        self.apply_calls.append(
            {
                "mode": mode,
                "upstream": upstream_url,
                "reason": reason,
                "dry_run": dry_run,
            }
        )
        result = DeploymentResult(
            changed=True,
            applied=not dry_run,
            dry_run=dry_run,
            mode=mode,
            upstream=upstream_url,
            verified=not dry_run,
            fragment_path=str(self.paths.fragment),
        )
        if not dry_run and self.applied:
            self.mode = mode
            self.upstream = upstream_url
            self.runtime = mode
            self.paths.fragment.parent.mkdir(parents=True, exist_ok=True)
            if mode == "proxy":
                text = (
                    "masquerade:\n  type: proxy\n  proxy:\n"
                    f"    url: {upstream_url}\n    rewriteHost: true\n"
                    "    insecure: false\n    xForwarded: false\n"
                )
            elif mode == "file":
                text = (
                    "masquerade:\n  type: file\n  file:\n"
                    f"    dir: {self.paths.site_dir}\n"
                )
            else:
                text = f"# masquerade mode: {mode}\n"
            self.paths.fragment.write_text(text, encoding="utf-8")
        return result


class FakeProber:
    """Prober fake: returns canned probes per candidate."""

    def __init__(self, mapping: dict[str, list[ProbeResult]]):
        self.mapping = mapping
        self.calls: list[str] = []

    def probe(self, candidate_: Candidate, *, url: str | None = None) -> ProbeResult:
        self.calls.append(candidate_.id)
        queue = self.mapping.get(candidate_.id)
        if not queue:
            return probe_result(candidate_.id, ok=False, error_kind="connect")
        if len(queue) > 1:
            return queue.pop(0)
        return queue[0]


def status_view(**overrides: Any) -> Status:
    values: dict[str, Any] = {
        "configured_mode": "auto",
        "effective_mode": "proxy",
        "upstream": "https://own-site.example/",
        "candidate_id": "own-site",
        "candidate_health": "healthy",
        "last_probe": None,
        "last_latency_ms": 180.0,
        "last_error": "",
        "evaluations": [],
        "fallback_ready": True,
        "certificate": None,
        "service_active": True,
        "runtime_mode": "proxy",
        "fragment_path": "/etc/hyvpn/masquerade.fragment.yaml",
        "site_dir": "/var/lib/hyvpn/masquerade/site",
        "state_path": "/var/lib/hyvpn/masquerade/state.json",
        "config_path": "/etc/hyvpn/masquerade.json",
        "capabilities": capabilities(),
        "pending_switch": None,
        "last_cycle_at": None,
        "candidates_enabled": 1,
        "candidates_total": 1,
    }
    values.update(overrides)
    return Status(**values)


def always(value: Callable[[], Any]) -> Callable[[], Any]:
    return value
