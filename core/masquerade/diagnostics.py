"""Read-only environment diagnostics.

The production VPS must be able to describe itself without a developer logging
in. Everything here is read-only and redacted: no secret value is ever read,
printed or returned. Only the *names* of environment keys are reported.

The report answers the questions that actually block a deployment:

* which Hysteria2 binary runs, in which version, and what it supports;
* which systemd unit and service user own the service;
* where the runtime configuration really lives;
* whether the certificate on disk covers the configured domain;
* who owns the files the engine has to write;
* what is currently listening on the Hysteria2 port;
* what masquerade configuration is deployed right now — including an upstream
  that is not in the candidate registry, which is how a hand-edited
  "masquerade: google" gets noticed.
"""

from __future__ import annotations

import ipaddress
import platform
import re
import shutil
import socket
import subprocess
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from core.cert_service import find_cert_file

from .capabilities import Capabilities, detect
from .config import Paths, load_config
from .render import describe_masquerade, extract_masquerade

SECRET_KEY_HINTS = ("SECRET", "TOKEN", "PASSWORD", "KEY", "PASS")

STATIC_CHECKS = (
    ("/etc/hyvpn", 0o750),
    ("/var/lib/hyvpn", 0o750),
    ("/var/lib/hysteria", 0o750),
)


def _run(
    args: list[str],
    *,
    timeout: float = 15.0,
    runner: Callable[..., Any] | None = None,
) -> subprocess.CompletedProcess | None:
    execute = runner or subprocess.run
    try:
        return execute(
            args, capture_output=True, text=True, timeout=timeout, check=False
        )
    except (OSError, subprocess.SubprocessError):
        return None


def read_os_release(path: str = "/etc/os-release") -> dict[str, str]:
    values: dict[str, str] = {}
    try:
        text = Path(path).read_text(encoding="utf-8")
    except OSError:
        return values
    for line in text.splitlines():
        if "=" not in line or line.startswith("#"):
            continue
        key, _, value = line.partition("=")
        values[key.strip()] = value.strip().strip('"').strip("'")
    return values


def owner_of(path: Path) -> dict[str, Any]:
    try:
        info = path.stat()
    except OSError as exc:
        return {"path": str(path), "exists": False, "error": str(exc)}
    payload: dict[str, Any] = {
        "path": str(path),
        "exists": True,
        "mode": oct(info.st_mode & 0o777),
        "size": info.st_size,
    }
    try:
        import grp
        import pwd

        payload["owner"] = pwd.getpwuid(info.st_uid).pw_name
        payload["group"] = grp.getgrgid(info.st_gid).gr_name
    except (ImportError, KeyError):  # pragma: no cover - Windows / unknown ids
        payload["owner"] = str(info.st_uid)
        payload["group"] = str(info.st_gid)
    return payload


def unit_info(service: str, runner: Callable[..., Any] | None = None) -> dict[str, Any]:
    result = _run(
        [
            "systemctl",
            "show",
            service,
            "--property=FragmentPath,User,Group,ActiveState,ExecMainStartTimestamp",
            "--no-pager",
        ],
        runner=runner,
    )
    if result is None or result.returncode != 0:
        return {"service": service, "available": False}
    payload: dict[str, Any] = {"service": service, "available": True}
    for line in (result.stdout or "").splitlines():
        if "=" in line:
            key, _, value = line.partition("=")
            payload[key] = value
    return payload


def listening_sockets(
    port: int, runner: Callable[..., Any] | None = None
) -> dict[str, Any]:
    """Report who listens on ``port`` (TCP and UDP).

    ``ss`` is part of iproute2, which this project already requires; there is
    no netstat fallback because a missing iproute2 is itself worth reporting.
    """
    info: dict[str, Any] = {"port": port, "tcp": [], "udp": [], "tool": "ss"}
    if not shutil.which("ss"):
        info["tool"] = ""
        info["error"] = "`ss` is not installed (iproute2)"
        return info
    result = _run(["ss", "-H", "-lntu"], runner=runner)
    if result is None or result.returncode != 0:
        info["error"] = "`ss -H -lntu` failed"
        return info

    for line in (result.stdout or "").splitlines():
        fields = line.split()
        if len(fields) < 5:
            continue
        netid = fields[0].lower()
        address, _, port_text = fields[4].rpartition(":")
        try:
            local_port = int(port_text)
        except ValueError:
            continue
        if local_port != port:
            continue
        entry = {"local": fields[4]}
        if len(fields) > 6:
            entry["process"] = " ".join(fields[6:])
        if "udp" in netid:
            info["udp"].append(entry)
        else:
            info["tcp"].append(entry)
    return info


def openssl_sans(path: Path, runner: Callable[..., Any] | None = None) -> list[str]:
    result = _run(
        ["openssl", "x509", "-in", str(path), "-noout", "-ext", "subjectAltName"],
        runner=runner,
    )
    text = ""
    if result is not None and result.returncode == 0:
        text = result.stdout or ""
    if not text:
        result = _run(
            ["openssl", "x509", "-in", str(path), "-noout", "-text"], runner=runner
        )
        text = (result.stdout or "") if result is not None else ""
    names: list[str] = []
    for match in re.finditer(r"DNS:([^,\s]+)", text):
        name = match.group(1).strip()
        if name and name not in names:
            names.append(name)
    return names


def is_private_destination(url: str) -> tuple[bool, str]:
    """True when an upstream URL points at a non-public address literal/DNS name."""
    from urllib.parse import urlsplit

    try:
        host = urlsplit(url).hostname or ""
    except ValueError:
        return True, "malformed URL"
    if not host:
        return True, "no host"
    if host in {"localhost", "localhost.localdomain"}:
        return True, "localhost"
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False, ""
    if (
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_reserved
        or address.is_multicast
        or address.is_unspecified
    ):
        return True, "non-public address"
    return False, ""


@dataclass
class DiagnosticReport:
    domain: str
    sections: dict[str, Any] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    capabilities: Capabilities | None = None

    @property
    def ok(self) -> bool:
        return not self.errors

    def to_json(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "domain": self.domain,
            "capabilities": self.capabilities.to_json() if self.capabilities else None,
            "sections": self.sections,
            "warnings": self.warnings,
            "errors": self.errors,
        }


def collect(
    paths: Paths,
    *,
    domain: str,
    server_port: int = 443,
    acme_dir: str = "/var/lib/hysteria/acme",
    runner: Callable[..., Any] | None = None,
    resolver: Callable[[str], list[str]] | None = None,
) -> DiagnosticReport:
    """Collect everything the installer/doctor needs to decide."""
    report = DiagnosticReport(domain=domain)

    os_release = read_os_release()
    report.sections["system"] = {
        "distribution": os_release.get("PRETTY_NAME") or os_release.get("NAME") or "unknown",
        "distribution_id": os_release.get("ID", ""),
        "version_id": os_release.get("VERSION_ID", ""),
        "kernel": platform.release(),
        "architecture": platform.machine(),
        "python": platform.python_version(),
        "hostname": socket.gethostname(),
    }

    capabilities = detect(str(paths.hysteria_binary), runner)
    report.capabilities = capabilities
    report.sections["hysteria"] = capabilities.to_json()
    if not capabilities.present:
        report.errors.append(capabilities.error or "hysteria binary not found")
    elif not capabilities.supports_masquerade:
        report.errors.append(
            f"hysteria {capabilities.version} does not support masquerade "
            "(needs 2.0.0 or newer)"
        )

    report.sections["service"] = unit_info(paths.service, runner)
    if not report.sections["service"].get("available"):
        report.warnings.append(
            f"{paths.service} is not visible to systemd (running outside the VPS?)"
        )

    report.sections["paths"] = {
        "config": owner_of(paths.config),
        "state_dir": owner_of(paths.state_dir),
        "site_dir": owner_of(paths.site_dir),
        "fragment": owner_of(paths.fragment),
        "fragment_last_good": owner_of(
            paths.fragment.with_name(paths.fragment.name + ".last-good")
        ),
        "runtime_config": owner_of(paths.runtime_config),
        "template": owner_of(paths.template),
        "acme_dir": owner_of(Path(acme_dir)),
        "hysteria_binary": owner_of(paths.hysteria_binary),
    }
    for raw_path, expected in STATIC_CHECKS:
        path = Path(raw_path)
        if not path.exists():
            continue
        actual = owner_of(path)
        try:
            mode = int(str(actual.get("mode", "0o0")), 8)
        except ValueError:  # pragma: no cover
            continue
        if mode & 0o777 != expected:
            report.warnings.append(
                f"{raw_path} has mode {actual.get('mode')} (expected {oct(expected)})"
            )
        if actual.get("owner") != "root" and path == Path("/etc/hyvpn"):
            report.warnings.append(f"{raw_path} is not owned by root")

    certificate_path = find_cert_file(domain, acme_dir) if domain else None
    if certificate_path is None:
        report.sections["certificate"] = {
            "found": False,
            "acme_dir": acme_dir,
            "note": "Hysteria2 obtains the certificate on the first connection",
        }
        report.warnings.append(
            f"no certificate for {domain or '<no domain>'} under {acme_dir}"
        )
    else:
        sans = openssl_sans(certificate_path, runner)
        report.sections["certificate"] = {
            "found": True,
            "path": str(certificate_path),
            "sans": sans,
            "covers_domain": bool(domain) and (domain in sans or f"*.{domain}" in sans),
            "owner": owner_of(certificate_path),
        }
        if domain and domain not in sans:
            report.errors.append(
                f"the certificate at {certificate_path} does not cover {domain} "
                f"(SANs: {', '.join(sans) or 'none'})"
            )

    report.sections["ports"] = listening_sockets(server_port, runner)

    try:
        config = load_config(paths)
        registry = {candidate.url for candidate in config.candidates}
        report.sections["registry"] = {
            "mode": config.mode,
            "candidates": [candidate.to_json() for candidate in config.candidates],
            "path": str(paths.config),
        }
    except Exception as exc:  # noqa: BLE001 - the report must still be produced
        registry = set()
        report.sections["registry"] = {"error": str(exc), "path": str(paths.config)}
        report.errors.append(f"masquerade.json cannot be used: {exc}")

    installed: dict[str, Any] | None = None
    for label, path in (
        ("runtime", paths.runtime_config),
        ("fragment", paths.fragment),
    ):
        try:
            text = path.read_text(encoding="utf-8")
        except OSError:
            continue
        section = extract_masquerade(text)
        if section is None:
            continue
        installed = describe_masquerade(section)
        installed["source"] = str(path)
        installed["source_kind"] = label
        break
    if installed is None:
        installed = {"mode": "none", "upstream": None, "source": None}
    report.sections["masquerade"] = installed

    upstream = installed.get("upstream")
    if installed.get("mode") == "proxy" and upstream:
        if upstream not in registry:
            report.warnings.append(
                f"the deployed upstream {upstream} is not in the candidate "
                "registry: it was set outside `hyvpn masquerade`"
            )
        private, reason = is_private_destination(str(upstream))
        if private:
            report.errors.append(
                f"the deployed upstream {upstream} points at a non-public "
                f"destination ({reason})"
            )
        if installed.get("insecure"):
            report.errors.append(
                "the deployed upstream disables certificate verification "
                "(masquerade.proxy.insecure: true)"
            )

    env_files = {
        "core": Path("/etc/hyvpn/.env.core"),
        "bot": Path("/etc/hyvpn/.env.bot"),
        "hysteria": Path("/etc/hyvpn/.env.hysteria"),
    }
    report.sections["environment"] = {
        name: {
            "path": str(path),
            "exists": path.exists(),
            # Only key names are reported: values are secrets.
            "keys": _env_keys(path),
        }
        for name, path in env_files.items()
    }

    return report


def _env_keys(path: Path) -> list[str]:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return []
    keys: list[str] = []
    for line in text.splitlines():
        if "=" not in line or line.lstrip().startswith("#"):
            continue
        key = line.split("=", 1)[0].strip()
        if key:
            secret = any(hint in key.upper() for hint in SECRET_KEY_HINTS)
            keys.append(key + ("=<redacted>" if secret else ""))
    return keys
