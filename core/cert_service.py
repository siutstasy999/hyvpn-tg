"""TLS certificate expiry reporting.

Hysteria2 obtains its certificate through ACME and stores it under its ACME
directory, owned by the ``hysteria`` user with restrictive permissions. The
unprivileged bot and core services therefore read a small JSON snapshot that
``bin/cert_probe.py`` refreshes as root (hy-certwatch.timer). Reading the
certificate directly is kept as a fallback for setups without the timer.
"""

from __future__ import annotations

import json
import re
import subprocess
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_ACME_DIR = "/var/lib/hysteria/acme"
DEFAULT_STATUS_PATH = "/var/lib/hyvpn/cert.json"

_OPENSSL_DATE = re.compile(r"notAfter=(.+)")


# Why the certificate state is what it is. Kept explicit instead of parsing
# the error text: the bot words "not issued yet" and "cannot read it" very
# differently, and only one of them is worth alarming the operator about.
VALID = "valid"          # parsed, expiry known
MISSING = "missing"      # ACME has not issued it yet
UNREADABLE = "unreadable"  # exists, but this process may not read it
ERROR = "error"          # found and readable, but could not be parsed


@dataclass(frozen=True)
class CertInfo:
    domain: str
    not_after: datetime | None = None
    issuer: str = ""
    source: str = "unknown"
    error: str = ""
    state: str = MISSING

    @property
    def known(self) -> bool:
        return self.not_after is not None

    @property
    def missing(self) -> bool:
        """True while Hysteria2 has simply not obtained a certificate yet."""
        return not self.known and self.state == MISSING

    @property
    def days_left(self) -> int | None:
        if self.not_after is None:
            return None
        delta = self.not_after - datetime.now(timezone.utc)
        return int(delta.total_seconds() // 86400)

    @property
    def expired(self) -> bool:
        days = self.days_left
        return days is not None and days < 0

    def to_json(self) -> str:
        payload = asdict(self)
        payload["not_after"] = (
            self.not_after.astimezone(timezone.utc).isoformat()
            if self.not_after
            else None
        )
        payload["days_left"] = self.days_left
        payload["checked_at"] = datetime.now(timezone.utc).isoformat()
        return json.dumps(payload, ensure_ascii=False, indent=2)


def find_cert_file(domain: str, acme_dir: str = DEFAULT_ACME_DIR) -> Path | None:
    """Locate the leaf certificate inside a certmagic-style ACME directory."""
    root = Path(acme_dir)
    if not root.exists():
        return None

    candidates: list[Path] = []
    # certmagic layout: <acme>/certificates/<ca-host-directory>/<domain>/<domain>.crt
    candidates.extend(root.glob(f"certificates/*/{domain}/{domain}.crt"))
    candidates.extend(root.glob(f"certificates/*/{domain}/*.crt"))
    candidates.extend(root.glob(f"**/{domain}.crt"))
    candidates.extend(root.glob("**/*.crt"))

    for candidate in candidates:
        if candidate.is_file():
            return candidate
    return None


def _parse_with_openssl(path: Path) -> tuple[datetime | None, str]:
    try:
        result = subprocess.run(
            ["openssl", "x509", "-in", str(path), "-noout", "-enddate", "-issuer"],
            capture_output=True,
            text=True,
            timeout=10,
            check=True,
        )
    except (OSError, subprocess.SubprocessError):
        return None, ""

    not_after = None
    issuer = ""
    for line in result.stdout.splitlines():
        match = _OPENSSL_DATE.match(line.strip())
        if match:
            not_after = _parse_openssl_date(match.group(1).strip())
        elif line.startswith("issuer="):
            issuer = line.split("=", 1)[1].strip()
    return not_after, issuer


def _parse_openssl_date(raw: str) -> datetime | None:
    # e.g. "Nov  5 12:00:00 2026 GMT"
    for fmt in ("%b %d %H:%M:%S %Y %Z", "%b %d %H:%M:%S %Y"):
        try:
            parsed = datetime.strptime(" ".join(raw.split()), fmt)
        except ValueError:
            continue
        return parsed.replace(tzinfo=timezone.utc)
    return None


def _parse_with_ssl_module(path: Path) -> tuple[datetime | None, str]:
    try:
        import ssl

        decoded = ssl._ssl._test_decode_cert(str(path))  # type: ignore[attr-defined]
    except Exception:
        return None, ""

    not_after = _parse_openssl_date(str(decoded.get("notAfter", "")))
    issuer = ""
    for group in decoded.get("issuer", ()):  # tuple of tuples
        for name, value in group:
            if name == "organizationName":
                issuer = value
    return not_after, issuer


def read_cert_file(domain: str, path: Path) -> CertInfo:
    if not path.is_file():
        return CertInfo(
            domain=domain,
            source="file",
            error="certificate not issued yet",
            state=MISSING,
        )
    try:
        path.read_bytes()
    except OSError as exc:
        return CertInfo(
            domain=domain,
            source="file",
            error=f"unreadable: {exc}",
            state=UNREADABLE,
        )

    not_after, issuer = _parse_with_openssl(path)
    if not_after is None:
        not_after, issuer = _parse_with_ssl_module(path)
    if not_after is None:
        return CertInfo(
            domain=domain,
            source="file",
            error="could not parse notAfter",
            state=ERROR,
        )
    return CertInfo(
        domain=domain,
        not_after=not_after,
        issuer=issuer,
        source="file",
        state=VALID,
    )


def read_status_file(path: str = DEFAULT_STATUS_PATH) -> CertInfo | None:
    """Read the snapshot written by bin/cert_probe.py, if present and fresh."""
    file_path = Path(path)
    if not file_path.is_file():
        return None
    try:
        payload = json.loads(file_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None

    raw = payload.get("not_after")
    not_after = None
    if raw:
        try:
            not_after = datetime.fromisoformat(raw)
        except ValueError:
            not_after = None
        if not_after is not None and not_after.tzinfo is None:
            not_after = not_after.replace(tzinfo=timezone.utc)

    state = str(payload.get("state", "")) or (VALID if not_after else MISSING)
    return CertInfo(
        domain=str(payload.get("domain", "")),
        not_after=not_after,
        issuer=str(payload.get("issuer", "")),
        source="snapshot",
        error=str(payload.get("error", "")),
        state=state,
    )


def get_cert_info(
    domain: str,
    acme_dir: str = DEFAULT_ACME_DIR,
    status_path: str = DEFAULT_STATUS_PATH,
) -> CertInfo:
    """Best-effort certificate info: snapshot first, then the file itself."""
    snapshot = read_status_file(status_path)
    if snapshot is not None and snapshot.known:
        return snapshot

    cert_file = find_cert_file(domain, acme_dir)
    if cert_file is not None:
        info = read_cert_file(domain, cert_file)
        if info.known:
            return info
        if snapshot is None:
            return info

    if snapshot is not None:
        return snapshot
    return CertInfo(
        domain=domain, error="certificate not issued yet", state=MISSING
    )
