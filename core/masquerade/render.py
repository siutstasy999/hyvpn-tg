"""Rendering and validation of the masquerade part of Hysteria's config.

The repository keeps one template (``hysteria-server.yaml``) that owns the
parts of the configuration this project must not touch: ``listen``, ``acme``,
``auth`` and ``trafficStats``. The masquerade section is a *fragment*: a small
YAML document that ``bin/render_hysteria_config.py`` substitutes into the
template at start-up. That split is what makes an upstream change a
single-file, atomic operation.

Only the documented Hysteria2 fields are emitted. ``insecure`` is always
written as ``false`` and ``type: none`` is expressed by omitting the section
entirely, because Hysteria2 documents "no masquerade section" as the disabled
state and answers 404 in that case.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .config import MasqConfig
from .models import EFFECTIVE_MODES

FRAGMENT_MARKER = "${MASQUERADE_YAML}"

FRAGMENT_HEADER = (
    "# Managed by `hyvpn masquerade` — do not edit by hand.\n"
    "# Rendered into {runtime} by bin/render_hysteria_config.py.\n"
)

# Exact key sets from the Hysteria2 server configuration reference.
MASQUERADE_KEYS = {"type", "proxy", "file", "string"}
PROXY_KEYS = {"url", "rewriteHost", "insecure", "xForwarded"}
FILE_KEYS = {"dir"}
STRING_KEYS = {"content", "headers", "statusCode"}


@dataclass
class ValidationResult:
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.errors

    def to_json(self) -> dict[str, Any]:
        return {"ok": self.ok, "errors": self.errors, "warnings": self.warnings}


# --------------------------------------------------------------------------- #
# building the fragment
# --------------------------------------------------------------------------- #

def masquerade_section(
    mode: str,
    config: MasqConfig,
    *,
    upstream_url: str | None = None,
    site_dir: str = "",
) -> dict[str, Any]:
    """Return the ``masquerade`` mapping for an effective mode."""
    if mode not in EFFECTIVE_MODES:
        raise ValueError(f"unknown effective masquerade mode: {mode}")

    if mode == "none":
        return {}
    if mode == "file":
        return {"type": "file", "file": {"dir": site_dir}}
    if mode == "string":
        return {
            "type": "string",
            "string": {
                "content": config.string_content,
                "headers": dict(config.string_headers),
                "statusCode": config.string_status_code,
            },
        }
    # proxy
    if not upstream_url:
        raise ValueError("proxy mode needs an upstream URL")
    return {
        "type": "proxy",
        "proxy": {
            "url": upstream_url,
            # The upstream is a normal virtual host: it needs its own Host.
            "rewriteHost": bool(config.rewrite_host),
            # Never true. Kept explicit so an operator reading the rendered
            # file cannot mistake the default for "not set".
            "insecure": False,
            "xForwarded": bool(config.x_forwarded),
        },
    }


def render_fragment(
    mode: str,
    config: MasqConfig,
    *,
    upstream_url: str | None = None,
    site_dir: str = "",
    runtime_config: str = "/run/hyvpn/hysteria-server.yaml",
) -> str:
    """Render the fragment file: header comment plus an optional section."""
    header = FRAGMENT_HEADER.format(runtime=runtime_config)
    if mode == "none":
        return header + (
            "# mode: none — Hysteria2 has no masquerade section, so "
            "unauthenticated HTTP requests receive 404.\n"
        )

    section = masquerade_section(
        mode, config, upstream_url=upstream_url, site_dir=site_dir
    )

    import yaml

    body = yaml.safe_dump(
        {"masquerade": section}, sort_keys=False, default_flow_style=False
    )
    return header + body


# --------------------------------------------------------------------------- #
# reading a fragment / runtime config
# --------------------------------------------------------------------------- #

def extract_masquerade(text: str) -> dict[str, Any] | None:
    """Return the ``masquerade`` mapping from a YAML document, if any."""
    import yaml

    try:
        payload = yaml.safe_load(text)
    except yaml.YAMLError:
        return None
    if not isinstance(payload, dict):
        return None
    section = payload.get("masquerade")
    return section if isinstance(section, dict) else None


def describe_masquerade(section: dict[str, Any] | None) -> dict[str, Any]:
    """Flatten a masquerade section into the fields the CLI and bot show."""
    if not section:
        return {"mode": "none", "upstream": None, "file": None, "string": None}
    mode = str(section.get("type") or "none")
    proxy = section.get("proxy") or {}
    file_section = section.get("file") or {}
    string_section = section.get("string") or {}
    return {
        "mode": mode if mode in EFFECTIVE_MODES else "unknown",
        "upstream": (proxy or {}).get("url"),
        "rewrite_host": (proxy or {}).get("rewriteHost"),
        "insecure": (proxy or {}).get("insecure"),
        "x_forwarded": (proxy or {}).get("xForwarded"),
        "file": (file_section or {}).get("dir"),
        "string": {
            "statusCode": (string_section or {}).get("statusCode"),
            "bytes": len(str((string_section or {}).get("content") or "")),
        }
        if string_section
        else None,
    }


def effective_mode_of(text: str) -> str:
    section = extract_masquerade(text)
    if not section:
        return "none"
    mode = str(section.get("type") or "none")
    return mode if mode in EFFECTIVE_MODES else "unknown"


# --------------------------------------------------------------------------- #
# validating a rendered server configuration
# --------------------------------------------------------------------------- #

def _expect_keys(
    payload: dict[str, Any], allowed: set[str], where: str, errors: list[str]
) -> None:
    unknown = set(payload) - allowed
    if unknown:
        errors.append(
            f"{where}: unknown key(s) {', '.join(sorted(unknown))}; Hysteria2 "
            f"supports only {', '.join(sorted(allowed))}"
        )


def validate_masquerade(
    section: Any,
    *,
    expected_mode: str | None = None,
    site_dir: str | None = None,
) -> ValidationResult:
    """Validate one ``masquerade`` mapping against the documented schema."""
    result = ValidationResult()
    if section is None:
        if expected_mode and expected_mode != "none":
            result.errors.append(
                f"masquerade section is missing but mode {expected_mode} was requested"
            )
        return result
    if not isinstance(section, dict):
        result.errors.append("masquerade must be a mapping")
        return result

    _expect_keys(section, MASQUERADE_KEYS, "masquerade", result.errors)
    mode = str(section.get("type") or "")
    if mode not in EFFECTIVE_MODES:
        result.errors.append(
            f"masquerade.type {mode!r} is not one of {', '.join(EFFECTIVE_MODES)}"
        )
        return result
    if expected_mode and expected_mode != mode:
        result.errors.append(
            f"masquerade.type is {mode!r} but {expected_mode!r} was requested"
        )

    for other in ("proxy", "file", "string"):
        if other != mode and other in section:
            result.errors.append(
                f"masquerade.{other} is present but type is {mode!r}; "
                "only the selected sub-section may be set"
            )

    if mode == "proxy":
        proxy = section.get("proxy")
        if not isinstance(proxy, dict):
            result.errors.append("masquerade.proxy is required for type 'proxy'")
            return result
        _expect_keys(proxy, PROXY_KEYS, "masquerade.proxy", result.errors)
        url = str(proxy.get("url") or "")
        parts = urlsplit(url)
        if parts.scheme not in {"https", "unix"}:
            result.errors.append(
                f"masquerade.proxy.url must be https:// (got {parts.scheme or 'none'!r})"
            )
        if parts.scheme == "https" and not parts.hostname:
            result.errors.append("masquerade.proxy.url has no host")
        for name in ("rewriteHost", "insecure", "xForwarded"):
            if name in proxy and not isinstance(proxy[name], bool):
                result.errors.append(f"masquerade.proxy.{name} must be true or false")
        if proxy.get("insecure"):
            result.errors.append(
                "masquerade.proxy.insecure must stay false: the upstream "
                "certificate is always verified"
            )
        if proxy.get("xForwarded"):
            result.warnings.append(
                "masquerade.proxy.xForwarded is enabled: the upstream will learn "
                "the visitor's address"
            )
    elif mode == "file":
        file_section = section.get("file")
        if not isinstance(file_section, dict):
            result.errors.append("masquerade.file is required for type 'file'")
            return result
        _expect_keys(file_section, FILE_KEYS, "masquerade.file", result.errors)
        directory = str(file_section.get("dir") or "")
        if not directory:
            result.errors.append("masquerade.file.dir must not be empty")
        else:
            path = Path(directory)
            if not path.is_dir():
                result.warnings.append(
                    f"masquerade.file.dir {directory} does not exist yet; it is "
                    "created together with the fallback site"
                )
            elif not (path / "index.html").is_file():
                result.errors.append(
                    f"masquerade.file.dir {directory} has no index.html; "
                    "visitors would see 404 pages"
                )
    elif mode == "string":
        string_section = section.get("string")
        if not isinstance(string_section, dict):
            result.errors.append("masquerade.string is required for type 'string'")
            return result
        _expect_keys(string_section, STRING_KEYS, "masquerade.string", result.errors)
        content = string_section.get("content")
        if not isinstance(content, str) or not content.strip():
            result.errors.append("masquerade.string.content must be a non-empty string")
        headers = string_section.get("headers")
        if headers is not None:
            if not isinstance(headers, dict):
                result.errors.append("masquerade.string.headers must be a mapping")
            else:
                for name, value in headers.items():
                    if not str(name).strip():
                        result.errors.append("masquerade.string.headers has an empty name")
                    if "\n" in str(value) or "\r" in str(value):
                        result.errors.append(
                            f"masquerade.string.headers[{name!r}] must be a single line"
                        )
        status = string_section.get("statusCode")
        if status is not None and (
            isinstance(status, bool) or not isinstance(status, int) or not 100 <= status <= 599
        ):
            result.errors.append(
                "masquerade.string.statusCode must be an integer between 100 and 599"
            )
    return result


def validate_runtime_config(
    text: str,
    *,
    domain: str,
    expected_mode: str | None = None,
    site_dir: str | None = None,
    require_acme: bool = True,
) -> ValidationResult:
    """Validate a complete rendered ``hysteria-server.yaml``.

    This is the last line of defence before a generated file is allowed to
    replace a working one. It re-checks the invariant that matters most to a
    VPN: the TLS identity of the server is derived from ``ACME_DOMAIN`` and is
    not touched by masquerade management.
    """
    import yaml

    result = ValidationResult()
    try:
        payload = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        result.errors.append(f"not valid YAML: {exc}")
        return result
    if not isinstance(payload, dict):
        result.errors.append("the server configuration must be a YAML mapping")
        return result

    if not payload.get("listen"):
        result.errors.append("listen is missing")

    acme = payload.get("acme")
    tls = payload.get("tls")
    if acme and tls:
        result.errors.append("acme and tls are mutually exclusive in Hysteria2")
    if require_acme and not acme and not tls:
        result.errors.append("neither acme nor tls is configured")
    if isinstance(acme, dict):
        domains = acme.get("domains")
        if not isinstance(domains, list) or not domains:
            result.errors.append("acme.domains is missing")
        elif domain and domain.lower() not in {
            str(item).lower() for item in domains
        }:
            result.errors.append(
                f"acme.domains {domains!r} does not contain the server domain {domain!r}"
            )
    if isinstance(tls, dict) and tls.get("insecure"):
        result.errors.append("tls.insecure would disable certificate verification")

    guard = payload.get("sniGuard")
    if guard is not None and str(guard) not in {"strict", "dns-san"}:
        result.errors.append(
            f"sniGuard is {guard!r}; only 'strict' or 'dns-san' keep SNI validation on"
        )

    auth = payload.get("auth")
    if auth is not None and not isinstance(auth, dict):
        result.errors.append("auth must be a mapping")

    masquerade = payload.get("masquerade")
    masquerade_result = validate_masquerade(
        masquerade, expected_mode=expected_mode, site_dir=site_dir
    )
    result.errors.extend(masquerade_result.errors)
    result.warnings.extend(masquerade_result.warnings)
    return result
