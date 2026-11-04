"""Data model of the Hysteria2 masquerade subsystem.

Everything here is plain data: no I/O, no network, no process management.
The rest of the package reads and writes these objects, which keeps the
selection logic testable without touching a real server.

Terminology, because the three TLS-adjacent concepts in Hysteria2 are easy to
mix up:

* **TLS / SNI** — the certificate of *this* server, issued by ACME for
  ``ACME_DOMAIN``. It is never chosen by the masquerade engine.
* **Masquerade upstream** — the content source Hysteria2 shows to visitors
  that do not authenticate. It is server-side only and has nothing to do with
  the client's SNI.
* **REALITY** — an Xray concept; it does not exist in Hysteria2 and is not
  modelled here.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlsplit

# Effective masquerade modes. "auto" is a *management* mode: it picks one of
# the four concrete modes below. It is never written to Hysteria's config.
EFFECTIVE_MODES: tuple[str, ...] = ("none", "file", "proxy", "string")
MANAGEMENT_MODES: tuple[str, ...] = ("auto",) + EFFECTIVE_MODES

# Health vocabulary shared by the CLI, the bot and the monitor.
HEALTHY = "healthy"
DEGRADED = "degraded"
UNHEALTHY = "unhealthy"
UNKNOWN = "unknown"

CANDIDATE_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,62}$")


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def iso(moment: datetime | None) -> str | None:
    if moment is None:
        return None
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(timezone.utc).isoformat()


def parse_iso(raw: Any) -> datetime | None:
    if not raw:
        return None
    try:
        parsed = datetime.fromisoformat(str(raw))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


@dataclass(frozen=True)
class Candidate:
    """An administrator-approved upstream for ``masquerade.proxy``.

    ``last_success``/``last_failure``/``latency_ms``/``health`` are runtime
    observations and live in the state file, not in the registry: the registry
    stays a small file an administrator can edit by hand.
    """

    id: str
    url: str
    enabled: bool = True
    priority: int = 0
    description: str = ""

    def to_json(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "url": self.url,
            "enabled": self.enabled,
            "priority": self.priority,
            "description": self.description,
        }

    @classmethod
    def from_json(cls, payload: Any) -> Candidate:
        if not isinstance(payload, dict):
            raise ValueError("candidate must be a JSON object")
        unknown = set(payload) - {"id", "url", "enabled", "priority", "description"}
        if unknown:
            raise ValueError(
                f"unknown candidate field(s): {', '.join(sorted(unknown))}"
            )
        candidate_id = str(payload.get("id", "")).strip()
        url = str(payload.get("url", "")).strip()
        if not CANDIDATE_ID_RE.match(candidate_id):
            raise ValueError(
                f"invalid candidate id {candidate_id!r}: use lowercase letters, "
                "digits, dot, dash or underscore (max 63 chars)"
            )
        priority = payload.get("priority", 0)
        if isinstance(priority, bool) or not isinstance(priority, int):
            raise ValueError(f"candidate {candidate_id}: priority must be an integer")
        return cls(
            id=candidate_id,
            url=url,
            enabled=bool(payload.get("enabled", True)),
            priority=priority,
            description=str(payload.get("description", "")),
        )


@dataclass(frozen=True)
class UrlCheck:
    """Result of validating an upstream URL before any network activity."""

    ok: bool
    url: str = ""
    scheme: str = ""
    host: str = ""
    port: int = 0
    path: str = "/"
    error: str = ""


def check_upstream_url(raw: str) -> UrlCheck:
    """Validate an upstream URL without touching the network.

    Only ``https://`` is accepted: ``masquerade.proxy.insecure`` stays false, so
    an ``http://`` upstream would either be refused by Hysteria or push an
    operator towards disabling verification, which this project forbids.
    """
    text = (raw or "").strip()
    if not text:
        return UrlCheck(False, error="empty URL")
    if len(text) > 2048:
        return UrlCheck(False, error="URL is too long")
    try:
        parts = urlsplit(text)
    except ValueError as exc:
        return UrlCheck(False, error=f"malformed URL: {exc}")

    scheme = parts.scheme.lower()
    if scheme != "https":
        return UrlCheck(
            False,
            error=f"upstream must use https:// (got {scheme or 'no scheme'!r})",
        )
    if parts.username or parts.password:
        return UrlCheck(False, error="URL must not contain credentials")
    if parts.fragment:
        return UrlCheck(False, error="URL must not contain a fragment")
    host = (parts.hostname or "").lower()
    if not host:
        return UrlCheck(False, error="URL has no host")
    try:
        # IP literals are allowed but must not be private; the address check in
        # the probe engine is authoritative, this is only a syntax guard.
        ipaddress.ip_address(host)
    except ValueError:
        if "." not in host:
            return UrlCheck(False, error=f"upstream host {host!r} is not a domain")
        if not re.match(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$", host):
            return UrlCheck(False, error=f"upstream host {host!r} is not a valid domain")
    try:
        port = parts.port or 443
    except ValueError:
        return UrlCheck(False, error="URL has an invalid port")
    if not 1 <= port <= 65535:
        return UrlCheck(False, error="URL port is out of range")
    path = parts.path or "/"
    if not path.startswith("/"):
        path = "/" + path
    if parts.query:
        path = f"{path}?{parts.query}"
    return UrlCheck(
        True,
        url=text,
        scheme=scheme,
        host=host,
        port=port,
        path=path,
    )


@dataclass(frozen=True)
class ProbeResult:
    """One application-level probe of one upstream."""

    candidate_id: str
    url: str
    ok: bool
    status: int | None = None
    error: str = ""
    error_kind: str = ""
    dns_ms: float = 0.0
    connect_ms: float = 0.0
    tls_ms: float = 0.0
    ttfb_ms: float = 0.0
    total_ms: float = 0.0
    redirects: tuple[str, ...] = ()
    content_type: str = ""
    body_bytes: int = 0
    content_ok: bool = False
    checked_at: datetime = field(default_factory=utc_now)

    @property
    def redirect_count(self) -> int:
        return len(self.redirects)

    def to_json(self) -> dict[str, Any]:
        return {
            "candidate": self.candidate_id,
            "url": self.url,
            "ok": self.ok,
            "status": self.status,
            "error": self.error,
            "error_kind": self.error_kind,
            "dns_ms": round(self.dns_ms, 1),
            "connect_ms": round(self.connect_ms, 1),
            "tls_ms": round(self.tls_ms, 1),
            "ttfb_ms": round(self.ttfb_ms, 1),
            "total_ms": round(self.total_ms, 1),
            "redirects": list(self.redirects),
            "content_type": self.content_type,
            "body_bytes": self.body_bytes,
            "content_ok": self.content_ok,
            "checked_at": iso(self.checked_at),
        }

    @classmethod
    def from_json(cls, payload: dict[str, Any]) -> ProbeResult:
        return cls(
            candidate_id=str(payload.get("candidate", "")),
            url=str(payload.get("url", "")),
            ok=bool(payload.get("ok")),
            status=payload.get("status"),
            error=str(payload.get("error", "")),
            error_kind=str(payload.get("error_kind", "")),
            dns_ms=float(payload.get("dns_ms") or 0),
            connect_ms=float(payload.get("connect_ms") or 0),
            tls_ms=float(payload.get("tls_ms") or 0),
            ttfb_ms=float(payload.get("ttfb_ms") or 0),
            total_ms=float(payload.get("total_ms") or 0),
            redirects=tuple(payload.get("redirects") or ()),
            content_type=str(payload.get("content_type", "")),
            body_bytes=int(payload.get("body_bytes") or 0),
            content_ok=bool(payload.get("content_ok")),
            checked_at=parse_iso(payload.get("checked_at")) or utc_now(),
        )


@dataclass(frozen=True)
class Sample:
    """Compact probe history entry, persisted between runs."""

    at: str
    ok: bool
    status: int | None = None
    total_ms: float = 0.0
    error_kind: str = ""
    redirects: tuple[str, ...] = ()

    def to_json(self) -> dict[str, Any]:
        return {
            "at": self.at,
            "ok": self.ok,
            "status": self.status,
            "total_ms": round(self.total_ms, 1),
            "error_kind": self.error_kind,
            "redirects": list(self.redirects),
        }

    @classmethod
    def from_json(cls, payload: dict[str, Any]) -> Sample:
        return cls(
            at=str(payload.get("at", "")),
            ok=bool(payload.get("ok")),
            status=payload.get("status"),
            total_ms=float(payload.get("total_ms") or 0),
            error_kind=str(payload.get("error_kind", "")),
            redirects=tuple(payload.get("redirects") or ()),
        )

    @classmethod
    def from_probe(cls, probe: ProbeResult) -> Sample:
        return cls(
            at=iso(probe.checked_at) or "",
            ok=probe.ok,
            status=probe.status,
            total_ms=probe.total_ms,
            error_kind=probe.error_kind,
            redirects=tuple(probe.redirects),
        )


@dataclass(frozen=True)
class Evaluation:
    """Scored health of one candidate, derived from its probe history."""

    candidate_id: str
    url: str
    score: float
    eligible: bool
    health: str
    availability: float
    samples: int
    successes: int
    mean_latency_ms: float
    latency_stdev_ms: float
    redirect_chains: int
    consecutive_failures: int
    last_success: str | None
    last_failure: str | None
    reasons: tuple[str, ...] = ()
    # The most recent probe succeeded (HTTP 2xx with a plausible body).
    latest_ok: bool = False
    # Good enough to keep serving traffic right now. Unlike ``eligible`` this
    # does not require a full track record, so a freshly configured candidate
    # can be kept once it answers correctly, while a challenger still has to
    # prove itself over several probes before it may replace it.
    retain_ok: bool = False
    # Enough probes to draw a conclusion about reliability.
    confident: bool = False

    def to_json(self) -> dict[str, Any]:
        return {
            "id": self.candidate_id,
            "url": self.url,
            "score": round(self.score, 4),
            "eligible": self.eligible,
            "retain_ok": self.retain_ok,
            "latest_ok": self.latest_ok,
            "confident": self.confident,
            "health": self.health,
            "availability": round(self.availability, 3),
            "samples": self.samples,
            "successes": self.successes,
            "mean_latency_ms": round(self.mean_latency_ms, 1),
            "latency_stdev_ms": round(self.latency_stdev_ms, 1),
            "redirect_chains": self.redirect_chains,
            "consecutive_failures": self.consecutive_failures,
            "last_success": self.last_success,
            "last_failure": self.last_failure,
            "reasons": list(self.reasons),
        }

    @classmethod
    def from_json(cls, payload: dict[str, Any]) -> Evaluation:
        return cls(
            candidate_id=str(payload.get("id", "")),
            url=str(payload.get("url", "")),
            score=float(payload.get("score") or 0),
            eligible=bool(payload.get("eligible")),
            health=str(payload.get("health", UNKNOWN)),
            availability=float(payload.get("availability") or 0),
            samples=int(payload.get("samples") or 0),
            successes=int(payload.get("successes") or 0),
            mean_latency_ms=float(payload.get("mean_latency_ms") or 0),
            latency_stdev_ms=float(payload.get("latency_stdev_ms") or 0),
            redirect_chains=int(payload.get("redirect_chains") or 0),
            consecutive_failures=int(payload.get("consecutive_failures") or 0),
            last_success=payload.get("last_success"),
            last_failure=payload.get("last_failure"),
            reasons=tuple(payload.get("reasons") or ()),
            latest_ok=bool(payload.get("latest_ok")),
            retain_ok=bool(payload.get("retain_ok")),
            confident=bool(payload.get("confident")),
        )


@dataclass(frozen=True)
class Thresholds:
    """Every knob of the probe/score/select pipeline.

    Defaults are deliberately conservative: they prefer keeping a working
    upstream over chasing a slightly faster one.
    """

    dns_timeout_seconds: float = 3.0
    connect_timeout_seconds: float = 4.0
    response_timeout_seconds: float = 6.0
    max_redirects: int = 3
    max_body_bytes: int = 65536
    min_body_bytes: int = 256
    content_types: tuple[str, ...] = ("text/html", "application/xhtml+xml")
    require_html_marker: bool = True

    latency_good_ms: float = 400.0
    latency_bad_ms: float = 2500.0
    min_score: float = 0.55
    min_samples: int = 3
    window: int = 10
    min_availability: float = 0.8

    probe_attempts: int = 2
    retry_delay_seconds: float = 0.5
    failover_after_failures: int = 1
    switch_margin: float = 0.15
    switch_confirmations: int = 3

    weight_tls: float = 0.20
    weight_http: float = 0.30
    weight_latency: float = 0.30
    weight_stability: float = 0.15
    weight_redirects: float = 0.05

    def normalised_weights(self) -> dict[str, float]:
        raw = {
            "tls": max(self.weight_tls, 0.0),
            "http": max(self.weight_http, 0.0),
            "latency": max(self.weight_latency, 0.0),
            "stability": max(self.weight_stability, 0.0),
            "redirects": max(self.weight_redirects, 0.0),
        }
        total = sum(raw.values())
        if total <= 0:
            return {key: 1 / len(raw) for key in raw}
        return {key: value / total for key, value in raw.items()}

    def to_json(self) -> dict[str, Any]:
        return {
            "dns_timeout_seconds": self.dns_timeout_seconds,
            "connect_timeout_seconds": self.connect_timeout_seconds,
            "response_timeout_seconds": self.response_timeout_seconds,
            "max_redirects": self.max_redirects,
            "max_body_bytes": self.max_body_bytes,
            "min_body_bytes": self.min_body_bytes,
            "content_types": list(self.content_types),
            "require_html_marker": self.require_html_marker,
            "latency_good_ms": self.latency_good_ms,
            "latency_bad_ms": self.latency_bad_ms,
            "min_score": self.min_score,
            "min_samples": self.min_samples,
            "window": self.window,
            "min_availability": self.min_availability,
            "probe_attempts": self.probe_attempts,
            "retry_delay_seconds": self.retry_delay_seconds,
            "failover_after_failures": self.failover_after_failures,
            "switch_margin": self.switch_margin,
            "switch_confirmations": self.switch_confirmations,
            "weight_tls": self.weight_tls,
            "weight_http": self.weight_http,
            "weight_latency": self.weight_latency,
            "weight_stability": self.weight_stability,
            "weight_redirects": self.weight_redirects,
        }

    @classmethod
    def from_json(cls, payload: Any) -> Thresholds:
        if payload is None:
            return cls()
        if not isinstance(payload, dict):
            raise ValueError("thresholds must be a JSON object")
        known = set(cls().to_json())
        unknown = set(payload) - known
        if unknown:
            raise ValueError(
                f"unknown threshold(s): {', '.join(sorted(unknown))}"
            )
        values = dict(payload)
        if "content_types" in values:
            raw = values["content_types"]
            if isinstance(raw, str):
                raw = [part.strip() for part in raw.split(",")]
            if not isinstance(raw, list):
                raise ValueError("content_types must be a list of strings")
            values["content_types"] = tuple(str(item).lower() for item in raw)
        defaults = cls()
        coerced: dict[str, Any] = {}
        for name, default in defaults.__dict__.items():
            if name not in values:
                continue
            value = values[name]
            if isinstance(default, bool):
                coerced[name] = bool(value)
            elif isinstance(default, int):
                if isinstance(value, bool) or not isinstance(value, (int, float)):
                    raise ValueError(f"threshold {name} must be a number")
                coerced[name] = int(value)
            elif isinstance(default, float):
                if isinstance(value, bool) or not isinstance(value, (int, float)):
                    raise ValueError(f"threshold {name} must be a number")
                coerced[name] = float(value)
            else:  # pragma: no cover - every other default is handled above
                coerced[name] = value
        result = cls(**{**defaults.__dict__, **coerced})
        if result.min_samples < 1:
            raise ValueError("min_samples must be at least 1")
        if result.window < result.min_samples:
            raise ValueError("window must be >= min_samples")
        if result.latency_bad_ms <= result.latency_good_ms:
            raise ValueError("latency_bad_ms must be greater than latency_good_ms")
        return result


@dataclass(frozen=True)
class Decision:
    """Why the engine selected what it selected. Persisted for auditability."""

    at: str
    mode: str
    candidate: str | None
    reason: str
    changed: bool
    evaluated: tuple[str, ...] = ()

    def to_json(self) -> dict[str, Any]:
        return {
            "at": self.at,
            "mode": self.mode,
            "candidate": self.candidate,
            "reason": self.reason,
            "changed": self.changed,
            "evaluated": list(self.evaluated),
        }

    @classmethod
    def from_json(cls, payload: dict[str, Any]) -> Decision:
        return cls(
            at=str(payload.get("at", "")),
            mode=str(payload.get("mode", "")),
            candidate=payload.get("candidate"),
            reason=str(payload.get("reason", "")),
            changed=bool(payload.get("changed")),
            evaluated=tuple(payload.get("evaluated") or ()),
        )
