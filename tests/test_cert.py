import json
import shutil
import subprocess
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from core.cert_service import (
    CertInfo,
    find_cert_file,
    get_cert_info,
    read_cert_file,
    read_status_file,
)

HAS_OPENSSL = shutil.which("openssl") is not None


def make_cert(directory: Path, domain: str, days: int) -> Path:
    """Create a self-signed certificate in a certmagic-like layout."""
    target = directory / "certificates" / "acme-v02.api.letsencrypt.org-directory" / domain
    target.mkdir(parents=True, exist_ok=True)
    crt = target / f"{domain}.crt"
    key = target / f"{domain}.key"
    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", str(key), "-out", str(crt),
            "-days", str(days), "-subj", f"/CN={domain}",
        ],
        check=True,
        capture_output=True,
    )
    return crt


def test_days_left_and_expired_flags():
    future = CertInfo(
        domain="example.com",
        not_after=datetime.now(timezone.utc) + timedelta(days=45, hours=1),
    )
    assert future.known
    assert future.days_left == 45
    assert not future.expired

    past = CertInfo(
        domain="example.com",
        not_after=datetime.now(timezone.utc) - timedelta(days=2),
    )
    assert past.expired
    assert past.days_left is not None and past.days_left < 0

    unknown = CertInfo(domain="example.com", error="nope")
    assert not unknown.known
    assert unknown.days_left is None
    assert not unknown.expired


@pytest.mark.skipif(not HAS_OPENSSL, reason="openssl is not installed")
def test_reads_a_real_certificate():
    with tempfile.TemporaryDirectory() as td:
        acme = Path(td) / "acme"
        crt = make_cert(acme, "vpn.example.com", 90)

        found = find_cert_file("vpn.example.com", str(acme))
        assert found == crt

        info = read_cert_file("vpn.example.com", crt)
        assert info.known, info.error
        assert 88 <= (info.days_left or 0) <= 90
        assert info.source == "file"

        # No snapshot yet: get_cert_info falls back to the file.
        combined = get_cert_info(
            "vpn.example.com", str(acme), str(Path(td) / "missing.json")
        )
        assert combined.known


def test_missing_certificate_is_reported_not_raised():
    with tempfile.TemporaryDirectory() as td:
        assert find_cert_file("vpn.example.com", str(Path(td) / "nowhere")) is None
        info = get_cert_info(
            "vpn.example.com", str(Path(td) / "nowhere"), str(Path(td) / "none.json")
        )
        assert not info.known
        assert info.error


def test_snapshot_round_trip():
    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "cert.json"
        original = CertInfo(
            domain="vpn.example.com",
            not_after=datetime.now(timezone.utc) + timedelta(days=30),
            issuer="Let's Encrypt",
            source="file",
        )
        path.write_text(original.to_json(), encoding="utf-8")

        payload = json.loads(path.read_text(encoding="utf-8"))
        assert payload["days_left"] in (29, 30)
        assert payload["checked_at"]

        restored = read_status_file(str(path))
        assert restored is not None
        assert restored.domain == "vpn.example.com"
        assert restored.issuer == "Let's Encrypt"
        assert restored.source == "snapshot"
        assert restored.days_left in (29, 30)

        # The snapshot wins over the filesystem, which the bot cannot read.
        assert get_cert_info("vpn.example.com", str(Path(td) / "nowhere"), str(path)).known


def test_corrupt_snapshot_is_ignored():
    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "cert.json"
        path.write_text("{not json", encoding="utf-8")
        assert read_status_file(str(path)) is None

        path.write_text(json.dumps({"domain": "x", "not_after": "nonsense"}), encoding="utf-8")
        info = read_status_file(str(path))
        assert info is not None and not info.known


@pytest.mark.skipif(not HAS_OPENSSL, reason="openssl is not installed")
def test_cert_probe_writes_a_readable_snapshot():
    with tempfile.TemporaryDirectory() as td:
        acme = Path(td) / "acme"
        make_cert(acme, "vpn.example.com", 60)
        out = Path(td) / "state" / "cert.json"

        result = subprocess.run(
            [
                "python", "bin/cert_probe.py",
                "vpn.example.com", str(acme), str(out),
            ],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, result.stderr
        assert out.is_file()
        info = read_status_file(str(out))
        assert info is not None and info.known
        assert 58 <= (info.days_left or 0) <= 60


def test_cert_probe_reports_missing_certificate():
    with tempfile.TemporaryDirectory() as td:
        out = Path(td) / "cert.json"
        result = subprocess.run(
            [
                "python", "bin/cert_probe.py",
                "vpn.example.com", str(Path(td) / "nowhere"), str(out),
            ],
            capture_output=True,
            text=True,
        )
        # A missing certificate is an expected state, still recorded on disk.
        assert result.returncode == 1
        assert out.is_file()
        info = read_status_file(str(out))
        assert info is not None and not info.known and info.error
