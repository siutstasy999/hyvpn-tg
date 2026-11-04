"""Application-level probing of masquerade upstreams.

A TCP connect or a TLS handshake proves nothing about a website: a CDN that
closes the connection on an unknown ``Host``, an origin that answers 403 to
the datacenter's IP range, or a redirect loop all complete a handshake. The
probe therefore performs a complete HTTP exchange with normal certificate
verification and only then decides whether the upstream is usable.

Design notes:

* No ``curl``, no ``requests``: the whole exchange is a few calls on
  ``socket``/``ssl``/``http.client``, so there is one hidden dependency less
  and the timeouts are ours.
* TLS verification is never disabled. There is no code path in this module
  that creates an unverified context.
* The vetted IP address is the address that gets connected to, not the name
  that was resolved, so a DNS answer cannot change between the check and the
  connection (rebinding).
* Destination addresses must be public. Loopback, private, link-local,
  multicast, reserved and unspecified addresses are rejected before connecting,
  which is what stops a candidate from turning the VPS into a proxy into its
  own network.
"""

from __future__ import annotations

import http.client
import inspect
import ipaddress
import logging
import queue
import socket
import ssl
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from urllib.parse import urljoin

from .models import (
    Candidate,
    ProbeResult,
    Thresholds,
    check_upstream_url,
    utc_now,
)

log = logging.getLogger(__name__)

USER_AGENT = "Mozilla/5.0 (compatible; hyvpn-masquerade-probe/1.0)"
MAX_REDIRECT_BODY = 8192


class ProbeError(Exception):
    """A probe failed at a specific stage."""

    def __init__(self, kind: str, message: str):
        super().__init__(message)
        self.kind = kind


@dataclass(frozen=True)
class RawResponse:
    status: int
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes = b""
    dns_ms: float = 0.0
    connect_ms: float = 0.0
    tls_ms: float = 0.0
    ttfb_ms: float = 0.0

    def header(self, name: str) -> str:
        return self.headers.get(name.lower(), "")


# --------------------------------------------------------------------------- #
# destination policy
# --------------------------------------------------------------------------- #

def classify_address(raw: str) -> tuple[bool, str]:
    """Return (allowed, reason) for one destination address."""
    try:
        address = ipaddress.ip_address(raw.split("%", 1)[0])
    except ValueError:
        return False, f"{raw!r} is not an IP address"
    if address.is_unspecified:
        return False, f"{raw} is the unspecified address"
    if address.is_loopback:
        return False, f"{raw} is a loopback address"
    if address.is_link_local:
        return False, f"{raw} is a link-local address"
    if address.is_multicast:
        return False, f"{raw} is a multicast address"
    if address.is_private:
        return False, f"{raw} is a private address"
    if address.is_reserved:
        return False, f"{raw} is a reserved address"
    if isinstance(address, ipaddress.IPv6Address) and address.is_site_local:
        return False, f"{raw} is a site-local address"
    return True, ""


# --------------------------------------------------------------------------- #
# DNS
# --------------------------------------------------------------------------- #

def _resolve(host: str, port: int) -> list[str]:
    infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    addresses: list[str] = []
    for _, _, _, _, sockaddr in infos:
        address = sockaddr[0]
        if address not in addresses:
            addresses.append(address)
    return addresses


def resolve_addresses(
    host: str,
    port: int,
    timeout: float,
    resolver: Callable[[str, int], list[str]] | None = None,
) -> tuple[list[str], float]:
    """Resolve ``host`` with a hard timeout. Returns (addresses, milliseconds)."""
    lookup = resolver or _resolve
    box: queue.Queue = queue.Queue(maxsize=1)

    def work() -> None:
        try:
            box.put(("ok", lookup(host, port)))
        except Exception as exc:  # noqa: BLE001 - re-raised in the caller
            box.put(("error", exc))

    worker = threading.Thread(target=work, name="masq-dns", daemon=True)
    started = time.monotonic()
    worker.start()
    try:
        kind, value = box.get(timeout=max(timeout, 0.1))
    except queue.Empty:
        raise ProbeError("dns", f"DNS lookup of {host} timed out") from None
    elapsed = (time.monotonic() - started) * 1000.0
    if kind == "error":
        raise ProbeError("dns", f"DNS lookup of {host} failed: {value}")
    addresses = list(value)
    if not addresses:
        raise ProbeError("dns", f"{host} has no A/AAAA records")
    return addresses, elapsed


# --------------------------------------------------------------------------- #
# TLS + HTTP
# --------------------------------------------------------------------------- #

def build_tls_context() -> ssl.SSLContext:
    """A client context with CA and hostname verification left enabled."""
    context = ssl.create_default_context()
    # Explicit for the reader: these are the defaults, and they stay that way.
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    return context


def https_get(
    host: str,
    port: int,
    path: str,
    addresses: list[str],
    *,
    timeout: float,
    max_body: int,
    context: ssl.SSLContext | None = None,
) -> RawResponse:
    """One HTTPS GET against a pre-vetted address, with certificate verification."""
    tls_context = context or build_tls_context()

    sock: socket.socket | None = None
    tls_sock: ssl.SSLSocket | None = None
    started = time.monotonic()
    try:
        address = addresses[0]
        family = socket.AF_INET6 if ":" in address else socket.AF_INET
        sock = socket.socket(family, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        connect_started = time.monotonic()
        sock.connect((address, port))
        connect_ms = (time.monotonic() - connect_started) * 1000.0

        tls_started = time.monotonic()
        tls_sock = tls_context.wrap_socket(sock, server_hostname=host)
        tls_ms = (time.monotonic() - tls_started) * 1000.0

        request = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"User-Agent: {USER_AGENT}\r\n"
            "Accept: text/html,application/xhtml+xml;q=0.9,*/*;q=0.5\r\n"
            "Accept-Encoding: identity\r\n"
            "Connection: close\r\n\r\n"
        ).encode("ascii", "replace")

        request_started = time.monotonic()
        tls_sock.sendall(request)
        response = http.client.HTTPResponse(tls_sock, method="GET")
        try:
            response.begin()
            ttfb_ms = (time.monotonic() - request_started) * 1000.0
            headers = {
                key.lower(): value for key, value in response.getheaders()
            }
            try:
                body = response.read(max_body)
            except (http.client.HTTPException, OSError):
                body = b""
        finally:
            response.close()

        return RawResponse(
            status=response.status,
            headers=headers,
            body=body,
            dns_ms=0.0,
            connect_ms=connect_ms,
            tls_ms=tls_ms,
            ttfb_ms=ttfb_ms,
        )
    except ssl.SSLCertVerificationError as exc:
        raise ProbeError(
            "tls_certificate", f"certificate rejected: {exc.verify_message or exc}"
        ) from exc
    except ssl.SSLError as exc:
        raise ProbeError("tls", f"TLS handshake failed: {exc}") from exc
    except TimeoutError as exc:
        raise ProbeError("timeout", "timed out") from exc
    except (http.client.HTTPException, ConnectionError, OSError) as exc:
        raise ProbeError("connect", f"connection failed: {exc}") from exc
    finally:
        elapsed = (time.monotonic() - started) * 1000.0
        if elapsed > timeout * 1000.0:
            log.debug("HTTPS GET took %.0f ms (budget %.0f ms)", elapsed, timeout * 1000.0)
        for closable in (tls_sock, sock):
            if closable is not None:
                try:
                    closable.close()
                except OSError:  # pragma: no cover
                    pass


# --------------------------------------------------------------------------- #
# probe engine
# --------------------------------------------------------------------------- #

class Prober:
    """Turns a :class:`Candidate` into a :class:`ProbeResult`.

    ``resolver`` and ``fetcher`` exist for tests: unit tests replace them with
    fakes so no test ever depends on a website being online.
    """

    def __init__(
        self,
        thresholds: Thresholds | None = None,
        *,
        resolver: Callable[[str, int], list[str]] | None = None,
        fetcher: Callable[..., RawResponse] | None = None,
        tls_context: ssl.SSLContext | None = None,
    ):
        self.thresholds = thresholds or Thresholds()
        self._resolver = resolver
        self._fetcher = fetcher or https_get
        self._context = tls_context
        # A test double may not accept the ``context`` keyword; decide once
        # instead of catching TypeError around the whole request.
        self._fetcher_takes_context = True
        try:
            parameters = inspect.signature(self._fetcher).parameters
            self._fetcher_takes_context = "context" in parameters or any(
                parameter.kind is inspect.Parameter.VAR_KEYWORD
                for parameter in parameters.values()
            )
        except (TypeError, ValueError):  # pragma: no cover - builtins
            self._fetcher_takes_context = True

    def _fetch(self, current, allowed):
        kwargs = {
            "timeout": self.thresholds.response_timeout_seconds,
            "max_body": self.thresholds.max_body_bytes,
        }
        if self._fetcher_takes_context:
            kwargs["context"] = self._context
        return self._fetcher(
            current.host,
            current.port,
            current.path,
            allowed,
            **kwargs,
        )

    # -- public API -------------------------------------------------------- #

    def probe(self, candidate: Candidate, *, url: str | None = None) -> ProbeResult:
        requested = url or candidate.url
        check = check_upstream_url(requested)
        if not check.ok:
            return self._failed(candidate.id, requested, "url", check.error)

        redirects: list[str] = []
        current = check
        visited = {current.url.rstrip("/")}
        dns_ms = connect_ms = tls_ms = ttfb_ms = 0.0
        total_started = time.monotonic()

        for hop in range(self.thresholds.max_redirects + 1):
            try:
                addresses, hop_dns_ms = resolve_addresses(
                    current.host,
                    current.port,
                    self.thresholds.dns_timeout_seconds,
                    self._resolver,
                )
            except ProbeError as exc:
                return self._failed(
                    candidate.id, requested, exc.kind, str(exc),
                    redirects=redirects,
                    total_ms=(time.monotonic() - total_started) * 1000.0,
                )
            dns_ms += hop_dns_ms

            allowed: list[str] = []
            for address in addresses:
                ok, reason = classify_address(address)
                if ok:
                    allowed.append(address)
                else:
                    log.info("candidate %s: refusing %s", candidate.id, reason)
            if not allowed:
                return self._failed(
                    candidate.id,
                    requested,
                    "blocked",
                    f"{current.host} resolves only to prohibited addresses "
                    f"({', '.join(addresses)})",
                    redirects=redirects,
                    dns_ms=dns_ms,
                    total_ms=(time.monotonic() - total_started) * 1000.0,
                )

            try:
                raw = self._fetch(current, allowed)
            except ProbeError as exc:
                return self._failed(
                    candidate.id,
                    requested,
                    exc.kind,
                    str(exc),
                    redirects=redirects,
                    dns_ms=dns_ms,
                    connect_ms=connect_ms,
                    tls_ms=tls_ms,
                    total_ms=(time.monotonic() - total_started) * 1000.0,
                )

            connect_ms += raw.connect_ms
            tls_ms += raw.tls_ms
            ttfb_ms += raw.ttfb_ms
            body = raw.body or b""

            if 300 <= raw.status < 400:
                location = raw.header("location")
                if not location:
                    return self._failed(
                        candidate.id,
                        requested,
                        "http",
                        f"HTTP {raw.status} without a Location header",
                        status=raw.status,
                        redirects=redirects,
                        dns_ms=dns_ms,
                        connect_ms=connect_ms,
                        tls_ms=tls_ms,
                        ttfb_ms=ttfb_ms,
                        total_ms=(time.monotonic() - total_started) * 1000.0,
                    )
                if hop >= self.thresholds.max_redirects:
                    return self._failed(
                        candidate.id,
                        requested,
                        "redirect",
                        f"more than {self.thresholds.max_redirects} redirects",
                        status=raw.status,
                        redirects=redirects,
                        dns_ms=dns_ms,
                        connect_ms=connect_ms,
                        tls_ms=tls_ms,
                        ttfb_ms=ttfb_ms,
                        total_ms=(time.monotonic() - total_started) * 1000.0,
                    )
                target = urljoin(current.url, location)
                next_check = check_upstream_url(target)
                if not next_check.ok:
                    return self._failed(
                        candidate.id,
                        requested,
                        "redirect",
                        f"redirect to an unusable URL: {next_check.error}",
                        status=raw.status,
                        redirects=redirects,
                        dns_ms=dns_ms,
                        connect_ms=connect_ms,
                        tls_ms=tls_ms,
                        ttfb_ms=ttfb_ms,
                        total_ms=(time.monotonic() - total_started) * 1000.0,
                    )
                key = next_check.url.rstrip("/")
                if key in visited:
                    return self._failed(
                        candidate.id,
                        requested,
                        "redirect_loop",
                        f"redirect loop at {next_check.url}",
                        status=raw.status,
                        redirects=redirects,
                        dns_ms=dns_ms,
                        connect_ms=connect_ms,
                        tls_ms=tls_ms,
                        ttfb_ms=ttfb_ms,
                        total_ms=(time.monotonic() - total_started) * 1000.0,
                    )
                visited.add(key)
                redirects.append(next_check.url)
                current = next_check
                continue

            content_type = raw.header("content-type").split(";", 1)[0].strip().lower()
            content_ok, content_error = self._check_content(raw.status, content_type, body)
            total_ms = (time.monotonic() - total_started) * 1000.0

            if 200 <= raw.status < 300 and content_ok:
                return ProbeResult(
                    candidate_id=candidate.id,
                    url=requested,
                    ok=True,
                    status=raw.status,
                    dns_ms=dns_ms,
                    connect_ms=connect_ms,
                    tls_ms=tls_ms,
                    ttfb_ms=ttfb_ms,
                    total_ms=total_ms,
                    redirects=tuple(redirects),
                    content_type=content_type,
                    body_bytes=len(body),
                    content_ok=True,
                    checked_at=utc_now(),
                )

            if not 200 <= raw.status < 300:
                return ProbeResult(
                    candidate_id=candidate.id,
                    url=requested,
                    ok=False,
                    status=raw.status,
                    error=f"HTTP {raw.status}",
                    error_kind="http_status",
                    dns_ms=dns_ms,
                    connect_ms=connect_ms,
                    tls_ms=tls_ms,
                    ttfb_ms=ttfb_ms,
                    total_ms=total_ms,
                    redirects=tuple(redirects),
                    content_type=content_type,
                    body_bytes=len(body),
                    content_ok=False,
                    checked_at=utc_now(),
                )

            return ProbeResult(
                candidate_id=candidate.id,
                url=requested,
                ok=False,
                status=raw.status,
                error=content_error,
                error_kind="content",
                dns_ms=dns_ms,
                connect_ms=connect_ms,
                tls_ms=tls_ms,
                ttfb_ms=ttfb_ms,
                total_ms=total_ms,
                redirects=tuple(redirects),
                content_type=content_type,
                body_bytes=len(body),
                content_ok=False,
                checked_at=utc_now(),
            )

        # The loop always returns; this keeps type checkers honest.
        return self._failed(  # pragma: no cover
            candidate.id, requested, "redirect", "too many redirects"
        )

    # -- helpers ----------------------------------------------------------- #

    def _check_content(
        self, status: int, content_type: str, body: bytes
    ) -> tuple[bool, str]:
        if not 200 <= status < 300:
            return False, f"HTTP {status}"
        allowed = self.thresholds.content_types
        if allowed and not any(
            content_type == item or content_type.startswith(item + "+")
            for item in allowed
        ):
            return False, (
                f"content type {content_type or 'missing'!r} is not one of "
                f"{', '.join(allowed)}"
            )
        if len(body) < self.thresholds.min_body_bytes:
            return False, (
                f"response body is only {len(body)} bytes "
                f"(minimum {self.thresholds.min_body_bytes})"
            )
        if self.thresholds.require_html_marker:
            lowered = body.lower()
            if not any(
                marker in lowered
                for marker in (b"<html", b"<!doctype html", b"<body")
            ):
                return False, "response body does not look like an HTML page"
        return True, ""

    def _failed(
        self,
        candidate_id: str,
        url: str,
        kind: str,
        error: str,
        *,
        status: int | None = None,
        redirects: list[str] | tuple[str, ...] = (),
        dns_ms: float = 0.0,
        connect_ms: float = 0.0,
        tls_ms: float = 0.0,
        ttfb_ms: float = 0.0,
        total_ms: float = 0.0,
    ) -> ProbeResult:
        return ProbeResult(
            candidate_id=candidate_id,
            url=url,
            ok=False,
            status=status,
            error=error,
            error_kind=kind,
            dns_ms=dns_ms,
            connect_ms=connect_ms,
            tls_ms=tls_ms,
            ttfb_ms=ttfb_ms,
            total_ms=total_ms,
            redirects=tuple(redirects),
            checked_at=utc_now(),
        )
