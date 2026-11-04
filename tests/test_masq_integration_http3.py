"""Optional integration test against a real Hysteria2 server.

Skipped unless ``HYVPN_HTTP3_TEST_DOMAIN`` points at a host that actually runs
this project's server. It is the only test in the suite that uses the network,
and it never runs in CI.

    HYVPN_HTTP3_TEST_DOMAIN=vpn.example.com \
    HYVPN_HTTP3_TEST_TIMEOUT=10 \
        pytest tests/test_masq_integration_http3.py -q

What it proves on the real host:

* the TLS certificate on the public endpoint verifies against the system CA
  store for that hostname (so masquerade did not move the TLS identity);
* the endpoint answers an ordinary HTTPS request over TCP, if anything listens
  on TCP/443 (optional);
* curl on this machine can speak HTTP/3 and the server serves the masquerade
  page over QUIC.
"""

from __future__ import annotations

import os

import pytest

from core.masquerade.deploy import check_http3, curl_supports_http3
from core.masquerade.models import Candidate, Thresholds
from core.masquerade.probe import Prober

DOMAIN = os.environ.get("HYVPN_HTTP3_TEST_DOMAIN", "")
TIMEOUT = float(os.environ.get("HYVPN_HTTP3_TEST_TIMEOUT", "10"))

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        not DOMAIN, reason="set HYVPN_HTTP3_TEST_DOMAIN to run the live check"
    ),
]


def test_the_live_certificate_verifies_over_tls():
    prober = Prober(Thresholds(response_timeout_seconds=TIMEOUT))
    result = prober.probe(Candidate(id="live", url=f"https://{DOMAIN}/"))
    # The page may be any masquerade mode; the TLS layer must be valid.
    assert result.error_kind != "tls_certificate", result.error
    assert result.error_kind != "dns", result.error


def test_curl_can_speak_http3_here():
    supported, detail = curl_supports_http3()
    if not supported:
        pytest.skip(detail)


def test_the_masquerade_page_is_served_over_http3():
    supported, detail = curl_supports_http3()
    if not supported:
        pytest.skip(detail)
    result = check_http3(DOMAIN, 443, timeout=TIMEOUT)
    assert result.available, result.detail
    assert result.ok, f"{result.detail} ({result.command})"
