"""Configuration and file locations of the masquerade subsystem.

Two kinds of configuration are kept apart on purpose:

* ``/etc/hyvpn/masquerade.json`` — administrator-authored. Modes, the
  candidate registry, thresholds and the local fallback settings. Edited by a
  human or by ``hyvpn masquerade candidates ...``; never rewritten by the
  health monitor.
* ``/var/lib/hyvpn/masquerade/state.json`` — observed state written by the
  engine (probe history, active candidate, decisions).

Both are JSON so an administrator can inspect and edit them with a text
editor without learning a new format.
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .models import (
    EFFECTIVE_MODES,
    MANAGEMENT_MODES,
    Candidate,
    Thresholds,
    check_upstream_url,
)

log = logging.getLogger(__name__)

CONFIG_VERSION = 1

DEFAULT_CONFIG_PATH = "/etc/hyvpn/masquerade.json"
DEFAULT_STATE_DIR = "/var/lib/hyvpn/masquerade"
DEFAULT_SITE_DIR = "/var/lib/hyvpn/masquerade/site"
DEFAULT_FRAGMENT_PATH = "/etc/hyvpn/masquerade.fragment.yaml"
DEFAULT_RUNTIME_CONFIG = "/run/hyvpn/hysteria-server.yaml"
DEFAULT_TEMPLATE_PATH = "/opt/hyvpn/hysteria-server.yaml"
DEFAULT_HYSTERIA_BINARY = "/usr/local/bin/hysteria"
DEFAULT_SERVICE = "hysteria-server.service"
DEFAULT_BACKUP_DIR = "/var/lib/hyvpn/masquerade/backups"

# Content that a local file/string fallback should serve. Kept in one place so
# `set-mode string` and the fallback site never disagree.
DEFAULT_STRING_CONTENT = (
    "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
    "<title>Web server</title></head><body><h1>Web server</h1>"
    "<p>The requested page is not available.</p></body></html>"
)
DEFAULT_STRING_HEADERS = {"content-type": "text/html; charset=utf-8"}


class ConfigError(ValueError):
    """The masquerade configuration is unusable and must not be applied."""


@dataclass(frozen=True)
class Paths:
    """Where the subsystem reads and writes. All values are absolute paths."""

    config: Path = Path(DEFAULT_CONFIG_PATH)
    state_dir: Path = Path(DEFAULT_STATE_DIR)
    site_dir: Path = Path(DEFAULT_SITE_DIR)
    fragment: Path = Path(DEFAULT_FRAGMENT_PATH)
    runtime_config: Path = Path(DEFAULT_RUNTIME_CONFIG)
    template: Path = Path(DEFAULT_TEMPLATE_PATH)
    backups: Path = Path(DEFAULT_BACKUP_DIR)
    hysteria_binary: Path = Path(DEFAULT_HYSTERIA_BINARY)
    service: str = DEFAULT_SERVICE

    @property
    def state_file(self) -> Path:
        return self.state_dir / "state.json"

    @property
    def request_dir(self) -> Path:
        return self.state_dir / "requests"

    @property
    def log_file(self) -> Path:
        return self.state_dir / "decisions.log"

    @classmethod
    def from_env(cls, env: dict[str, str] | None = None) -> Paths:
        source = os.environ if env is None else env

        def value(name: str, default: str) -> Path:
            raw = source.get(name)
            return Path(raw) if raw else Path(default)

        return cls(
            config=value("MASQ_CONFIG_PATH", DEFAULT_CONFIG_PATH),
            state_dir=value("MASQ_STATE_DIR", DEFAULT_STATE_DIR),
            site_dir=value("MASQ_SITE_DIR", DEFAULT_SITE_DIR),
            fragment=value("MASQ_FRAGMENT_PATH", DEFAULT_FRAGMENT_PATH),
            runtime_config=value("MASQ_RUNTIME_CONFIG", DEFAULT_RUNTIME_CONFIG),
            template=value("MASQ_TEMPLATE", DEFAULT_TEMPLATE_PATH),
            backups=value("MASQ_BACKUP_DIR", DEFAULT_BACKUP_DIR),
            hysteria_binary=value("HYSTERIA_BINARY", DEFAULT_HYSTERIA_BINARY),
            service=source.get("MASQ_SERVICE") or DEFAULT_SERVICE,
        )


@dataclass
class MasqConfig:
    """The administrator-controlled configuration."""

    mode: str = "auto"
    candidates: list[Candidate] = field(default_factory=list)
    thresholds: Thresholds = field(default_factory=Thresholds)
    rewrite_host: bool = True
    # Never defaulted to true and never settable through the CLI: an
    # unverified upstream TLS connection is not a configuration this project
    # ships.
    x_forwarded: bool = False
    string_content: str = DEFAULT_STRING_CONTENT
    string_headers: dict[str, str] = field(
        default_factory=lambda: dict(DEFAULT_STRING_HEADERS)
    )
    string_status_code: int = 200
    fallback_index: str = "index.html"
    version: int = CONFIG_VERSION

    # ---- validation ------------------------------------------------------ #

    def validate(self) -> list[str]:
        """Return a list of problems. Empty means the config is usable."""
        problems: list[str] = []
        if self.mode not in MANAGEMENT_MODES:
            problems.append(
                f"mode {self.mode!r} is not one of {', '.join(MANAGEMENT_MODES)}"
            )
        seen: set[str] = set()
        for candidate in self.candidates:
            if candidate.id in seen:
                problems.append(f"duplicate candidate id {candidate.id!r}")
            seen.add(candidate.id)
            check = check_upstream_url(candidate.url)
            if not check.ok:
                problems.append(f"candidate {candidate.id}: {check.error}")
            elif candidate.enabled and check.host == "localhost":
                problems.append(
                    f"candidate {candidate.id}: localhost is not a usable upstream"
                )
        try:
            self.thresholds.normalised_weights()
        except Exception as exc:  # pragma: no cover - defensive
            problems.append(f"thresholds: {exc}")
        if self.string_status_code < 100 or self.string_status_code > 599:
            problems.append("string_status_code must be between 100 and 599")
        if not self.string_content.strip():
            problems.append("string_content must not be empty")
        for name, value in self.string_headers.items():
            if not str(name).strip():
                problems.append("string_headers contains an empty header name")
            if "\n" in str(value) or "\r" in str(value):
                problems.append(f"header {name!r} must be a single line")
        return problems

    def enabled_candidates(self) -> list[Candidate]:
        return [candidate for candidate in self.candidates if candidate.enabled]

    def candidate(self, candidate_id: str) -> Candidate | None:
        for candidate in self.candidates:
            if candidate.id == candidate_id:
                return candidate
        return None

    def effective_mode(self, resolved: str | None = None) -> str:
        """Concrete mode to render: ``auto`` is resolved before this point."""
        mode = resolved or self.mode
        if mode == "auto":
            raise ConfigError("auto mode must be resolved before rendering a config")
        if mode not in EFFECTIVE_MODES:
            raise ConfigError(f"unknown masquerade mode: {mode}")
        return mode

    def to_json(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "mode": self.mode,
            "candidates": [candidate.to_json() for candidate in self.candidates],
            "thresholds": self.thresholds.to_json(),
            "proxy": {
                "rewriteHost": self.rewrite_host,
                "insecure": False,
                "xForwarded": self.x_forwarded,
            },
            "string": {
                "content": self.string_content,
                "headers": dict(self.string_headers),
                "statusCode": self.string_status_code,
            },
            "fallback": {"index": self.fallback_index},
        }

    @classmethod
    def from_json(cls, payload: Any) -> MasqConfig:
        if not isinstance(payload, dict):
            raise ConfigError("masquerade.json must contain a JSON object")
        known = {
            "version", "mode", "candidates", "thresholds", "proxy", "string",
            "fallback", "masquerade",
        }
        unknown = set(payload) - known
        if unknown:
            raise ConfigError(
                f"unknown key(s) in masquerade.json: {', '.join(sorted(unknown))}"
            )
        proxy = payload.get("proxy") or {}
        if not isinstance(proxy, dict):
            raise ConfigError("proxy must be a JSON object")
        unknown_proxy = set(proxy) - {"rewriteHost", "insecure", "xForwarded"}
        if unknown_proxy:
            raise ConfigError(
                "unknown proxy key(s): " + ", ".join(sorted(unknown_proxy))
            )
        if proxy.get("insecure"):
            raise ConfigError(
                "proxy.insecure must stay false: the upstream certificate is "
                "always verified"
            )
        string = payload.get("string") or {}
        if not isinstance(string, dict):
            raise ConfigError("string must be a JSON object")
        unknown_string = set(string) - {"content", "headers", "statusCode"}
        if unknown_string:
            raise ConfigError(
                "unknown string key(s): " + ", ".join(sorted(unknown_string))
            )
        headers = string.get("headers", DEFAULT_STRING_HEADERS)
        if not isinstance(headers, dict):
            raise ConfigError("string.headers must be a JSON object")
        fallback = payload.get("fallback") or {}
        if not isinstance(fallback, dict):
            raise ConfigError("fallback must be a JSON object")

        raw_candidates = payload.get("candidates", [])
        if not isinstance(raw_candidates, list):
            raise ConfigError("candidates must be a JSON list")
        candidates = [Candidate.from_json(item) for item in raw_candidates]

        config = cls(
            mode=str(payload.get("mode", "auto")),
            candidates=candidates,
            thresholds=Thresholds.from_json(payload.get("thresholds")),
            rewrite_host=bool(proxy.get("rewriteHost", True)),
            x_forwarded=bool(proxy.get("xForwarded", False)),
            string_content=str(string.get("content", DEFAULT_STRING_CONTENT)),
            string_headers={str(k): str(v) for k, v in headers.items()},
            string_status_code=int(string.get("statusCode", 200)),
            fallback_index=str(fallback.get("index", "index.html")),
            version=int(payload.get("version", CONFIG_VERSION)),
        )
        problems = config.validate()
        if problems:
            raise ConfigError("; ".join(problems))
        return config

    def copy(self) -> MasqConfig:
        return MasqConfig(
            mode=self.mode,
            candidates=list(self.candidates),
            thresholds=self.thresholds,
            rewrite_host=self.rewrite_host,
            x_forwarded=self.x_forwarded,
            string_content=self.string_content,
            string_headers=dict(self.string_headers),
            string_status_code=self.string_status_code,
            fallback_index=self.fallback_index,
            version=self.version,
        )


def default_config() -> MasqConfig:
    """Configuration a fresh install starts with.

    The candidate list is empty on purpose: an upstream must be an
    administrator-approved host, and proxying a third-party website without
    permission is exactly what this subsystem is meant to stop doing by
    accident. Until an administrator adds an authorised upstream, the server
    serves its own local site.
    """
    return MasqConfig(mode="auto", candidates=[])


def load_config(paths: Paths) -> MasqConfig:
    """Load the admin config, creating the default one when it is missing."""
    if not paths.config.exists():
        return default_config()
    try:
        payload = json.loads(paths.config.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ConfigError(f"cannot read {paths.config}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ConfigError(f"{paths.config} is not valid JSON: {exc}") from exc
    return MasqConfig.from_json(payload)


def write_config(paths: Paths, config: MasqConfig, *, target: Path | None = None) -> Path:
    """Atomically write the admin config with restrictive permissions."""
    destination = target or paths.config
    problems = config.validate()
    if problems:
        raise ConfigError("; ".join(problems))
    destination.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(config.to_json(), ensure_ascii=False, indent=2) + "\n"
    tmp = destination.with_name(destination.name + ".tmp")
    with open(tmp, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(tmp, destination)
    _set_owner_and_mode(destination, 0o640)
    return destination


def _set_owner_and_mode(path: Path, mode: int) -> None:
    """Apply mode (and, when running as root, root:hyvpn ownership)."""
    try:
        os.chmod(path, mode)
    except OSError as exc:  # pragma: no cover - unusual filesystem
        log.warning("could not chmod %s: %s", path, exc)
    geteuid = getattr(os, "geteuid", None)
    if geteuid is None or geteuid() != 0 or not hasattr(os, "chown"):
        return
    try:  # pragma: no cover - exercised on the server, not in unit tests
        import grp

        gid = grp.getgrnam("hyvpn").gr_gid
    except (ImportError, KeyError):  # pragma: no cover
        return
    try:  # pragma: no cover
        os.chown(path, 0, gid)
    except OSError as exc:  # pragma: no cover
        log.warning("could not chown %s: %s", path, exc)
