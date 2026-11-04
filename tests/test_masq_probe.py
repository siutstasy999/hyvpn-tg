"""Probing an upstream: every failure mode, without touching the network."""

from __future__ import annotations

import time

import pytest

from core.masquerade.models import Candidate, Thresholds, check_upstream_url
from core.masquerade.probe import (
    ProbeError,
    Prober,
    classify_address,
    resolve_addresses,
)
from tests.masq_fakes import Fetcher, Resolver, html_response

PUBLIC_V4 = "93.184.216.34"
PUBLIC_V6 = "2606:2800:220:1:248:1893:25c8:1946"
THRESHOLDS = Thresholds(retry_delay_seconds=0.0)


def candidate(url: str = "https://example.com/", candidate_id: str = "a") -> Candidate:
    return Candidate(id=candidate_id, url=url)


def make_prober(mapping: dict, fetcher: Fetcher, *, thresholds: Thresholds = THRESHOLDS):
    return Prober(thresholds, resolver=Resolver(mapping), fetcher=fetcher)


# --------------------------------------------------------------------------- #
# URL handling
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize(
    "url",
    [
        "http://example.com/",
        "ftp://example.com/",
        "example.com",
        "https://user:pass@example.com/",
        "https://example.com/#fragment",
        "https:///path",
        "https://exa_mple.com/",
        "",
    ],
)
def test_invalid_upstream_urls_are_rejected_locally(url):
    check = check_upstream_url(url)
    assert not check.ok
    assert check.error


def test_http_upstream_is_refused_with_an_explanation():
    check = check_upstream_url("http://example.com/")
    assert "https://" in check.error


def test_valid_url_is_normalised():
    check = check_upstream_url("https://Example.COM/path?a=1")
    assert check.ok
    assert check.host == "example.com"
    assert check.port == 443
    assert check.path == "/path?a=1"


def test_probe_of_an_invalid_url_never_opens_a_socket():
    fetcher = Fetcher({})
    prober = make_prober({"example.com": [PUBLIC_V4]}, fetcher)
    result = prober.probe(candidate("http://example.com/"))
    assert not result.ok
    assert result.error_kind == "url"
    assert fetcher.calls == []


# --------------------------------------------------------------------------- #
# destination policy
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize(
    "address",
    [
        "127.0.0.1",
        "10.1.2.3",
        "192.168.1.1",
        "169.254.169.254",
        "0.0.0.0",
        "224.0.0.1",
        "::1",
        "fe80::1",
        "fc00::1",
        "255.255.255.255",
    ],
)
def test_prohibited_destinations_are_classified(address):
    allowed, reason = classify_address(address)
    assert not allowed
    assert reason


def test_public_address_is_allowed():
    assert classify_address(PUBLIC_V4) == (True, "")
    assert classify_address(PUBLIC_V6) == (True, "")


def test_candidate_resolving_to_loopback_is_blocked_before_connecting():
    fetcher = Fetcher({})
    prober = make_prober({"example.com": ["127.0.0.1"]}, fetcher)
    result = prober.probe(candidate())
    assert not result.ok
    assert result.error_kind == "blocked"
    assert "prohibited" in result.error
    assert fetcher.calls == []


def test_mixed_answer_uses_only_the_public_address():
    fetcher = Fetcher({"example.com": html_response()})
    prober = make_prober({"example.com": ["10.0.0.5", PUBLIC_V4]}, fetcher)
    result = prober.probe(candidate())
    assert result.ok
    assert fetcher.calls[0]["addresses"] == [PUBLIC_V4]


# --------------------------------------------------------------------------- #
# DNS
# --------------------------------------------------------------------------- #

def test_dns_failure_is_reported_as_dns():
    prober = make_prober({"example.com": OSError("NXDOMAIN")}, Fetcher({}))
    result = prober.probe(candidate())
    assert not result.ok
    assert result.error_kind == "dns"
    assert "failed" in result.error


def test_empty_dns_answer_is_a_dns_failure():
    prober = make_prober({"example.com": []}, Fetcher({}))
    result = prober.probe(candidate())
    assert result.error_kind == "dns"


def test_dns_lookup_is_bounded_by_a_timeout():
    def slow(host: str, port: int) -> list[str]:
        time.sleep(0.5)
        return [PUBLIC_V4]

    started = time.monotonic()
    with pytest.raises(ProbeError) as excinfo:
        resolve_addresses("example.com", 443, 0.05, slow)
    assert excinfo.value.kind == "dns"
    assert "timed out" in str(excinfo.value)
    assert time.monotonic() - started < 0.4


# --------------------------------------------------------------------------- #
# TLS
# --------------------------------------------------------------------------- #

def test_certificate_rejection_is_not_retried_and_is_reported():
    fetcher = Fetcher(
        {"example.com": ProbeError("tls_certificate", "certificate has expired")}
    )
    prober = make_prober({"example.com": [PUBLIC_V4]}, fetcher)
    result = prober.probe(candidate())
    assert not result.ok
    assert result.error_kind == "tls_certificate"
    assert "expired" in result.error
    assert len(fetcher.calls) == 1


def test_wrong_hostname_is_a_certificate_error():
    fetcher = Fetcher(
        {
            "example.com": ProbeError(
                "tls_certificate", "hostname 'example.com' doesn't match 'other.example'"
            )
        }
    )
    result = make_prober({"example.com": [PUBLIC_V4]}, fetcher).probe(candidate())
    assert result.error_kind == "tls_certificate"
    assert "doesn't match" in result.error


# --------------------------------------------------------------------------- #
# HTTP
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("status", [403, 404, 500, 503])
def test_error_statuses_make_a_candidate_unhealthy(status):
    fetcher = Fetcher({"example.com": html_response(status=status)})
    result = make_prober({"example.com": [PUBLIC_V4]}, fetcher).probe(candidate())
    assert not result.ok
    assert result.error_kind == "http_status"
    assert result.status == status


def test_timeout_is_reported_as_timeout():
    fetcher = Fetcher({"example.com": ProbeError("timeout", "timed out")})
    result = make_prober({"example.com": [PUBLIC_V4]}, fetcher).probe(candidate())
    assert result.error_kind == "timeout"


def test_connection_refused_is_reported_as_connect():
    fetcher = Fetcher({"example.com": ProbeError("connect", "connection refused")})
    result = make_prober({"example.com": [PUBLIC_V4]}, fetcher).probe(candidate())
    assert result.error_kind == "connect"


# --------------------------------------------------------------------------- #
# redirects
# --------------------------------------------------------------------------- #

def test_redirect_loop_is_detected():
    fetcher = Fetcher(
        {
            "example.com": html_response(
                status=302, headers={"location": "https://example.com/"}
            )
        }
    )
    result = make_prober({"example.com": [PUBLIC_V4]}, fetcher).probe(candidate())
    assert not result.ok
    assert result.error_kind == "redirect_loop"


def test_redirect_chain_is_followed_and_recorded():
    fetcher = Fetcher(
        {
            "https://example.com/": html_response(
                status=301, headers={"location": "/final"}
            ),
            "https://example.com/final": html_response(),
        }
    )
    result = make_prober({"example.com": [PUBLIC_V4]}, fetcher).probe(candidate())
    assert result.ok
    assert result.redirects == ("https://example.com/final",)
    assert [call["path"] for call in fetcher.calls] == ["/", "/final"]


def test_too_many_redirects_is_refused():
    thresholds = Thresholds(max_redirects=1, retry_delay_seconds=0.0)
    fetcher = Fetcher(
        {
            "https://example.com/": html_response(
                status=302, headers={"location": "/one"}
            ),
            "https://example.com/one": html_response(
                status=302, headers={"location": "/two"}
            ),
        }
    )
    prober = Prober(thresholds, resolver=Resolver({"example.com": [PUBLIC_V4]}), fetcher=fetcher)
    result = prober.probe(candidate())
    assert not result.ok
    assert result.error_kind == "redirect"
    assert "more than 1" in result.error


def test_redirect_to_http_is_refused():
    fetcher = Fetcher(
        {
            "example.com": html_response(
                status=301, headers={"location": "http://example.com/"}
            )
        }
    )
    result = make_prober({"example.com": [PUBLIC_V4]}, fetcher).probe(candidate())
    assert not result.ok
    assert result.error_kind == "redirect"
    assert "https" in result.error


def test_redirect_without_location_is_an_http_error():
    fetcher = Fetcher({"example.com": html_response(status=302)})
    result = make_prober({"example.com": [PUBLIC_V4]}, fetcher).probe(candidate())
    assert result.error_kind == "http"


# --------------------------------------------------------------------------- #
# content
# --------------------------------------------------------------------------- #

def test_non_html_content_type_is_rejected():
    fetcher = Fetcher(
        {"example.com": html_response(content_type="application/json", body=b"{}" * 400)}
    )
    result = make_prober({"example.com": [PUBLIC_V4]}, fetcher).probe(candidate())
    assert not result.ok
    assert result.error_kind == "content"
    assert "content type" in result.error


def test_tiny_body_is_rejected():
    fetcher = Fetcher({"example.com": html_response(body=b"<html>hi</html>")})
    result = make_prober({"example.com": [PUBLIC_V4]}, fetcher).probe(candidate())
    assert result.error_kind == "content"
    assert "body" in result.error


def test_body_without_html_markers_is_rejected():
    fetcher = Fetcher(
        {"example.com": html_response(body=b"a" * 600)}
    )
    result = make_prober({"example.com": [PUBLIC_V4]}, fetcher).probe(candidate())
    assert result.error_kind == "content"
    assert "HTML" in result.error


def test_html_marker_check_can_be_disabled():
    thresholds = Thresholds(require_html_marker=False, retry_delay_seconds=0.0)
    fetcher = Fetcher({"example.com": html_response(body=b"a" * 600)})
    result = make_prober(
        {"example.com": [PUBLIC_V4]}, fetcher, thresholds=thresholds
    ).probe(candidate())
    assert result.ok


# --------------------------------------------------------------------------- #
# success
# --------------------------------------------------------------------------- #

def test_successful_probe_records_every_phase():
    fetcher = Fetcher({"example.com": html_response()})
    result = make_prober({"example.com": [PUBLIC_V4]}, fetcher).probe(candidate())
    assert result.ok
    assert result.status == 200
    assert result.content_ok
    assert result.body_bytes >= THRESHOLDS.min_body_bytes
    assert result.dns_ms >= 0
    assert result.connect_ms > 0
    assert result.tls_ms > 0
    assert result.ttfb_ms > 0
    assert result.total_ms > 0
    assert result.error_kind == ""


def test_probe_uses_the_vetted_address_and_the_original_hostname():
    fetcher = Fetcher({"example.com": html_response()})
    prober = make_prober({"example.com": [PUBLIC_V6]}, fetcher)
    prober.probe(candidate())
    call = fetcher.calls[0]
    assert call["host"] == "example.com"
    assert call["addresses"] == [PUBLIC_V6]
    assert call["max_body"] == THRESHOLDS.max_body_bytes
