"""Rendering the runtime Hysteria2 configuration.

The template in the repository owns the parts of the configuration this
project must never rewrite: ``listen``, ``acme``, ``auth`` and
``trafficStats``. Two things are injected into it:

* the ``${TRAFFIC_STATS_SECRET}`` / ``${ACME_DOMAIN}`` / ``${ACME_EMAIL}``
  values, which come from ``/etc/hyvpn/.env.hysteria``;
* the masquerade fragment at ``${MASQUERADE_YAML}``.

Keeping the fragment as data instead of editing the template is what makes an
upstream change a one-file, atomic operation, and it lets the renderer fall
back to the last known-good fragment if a fresh one is unreadable. The service
must always be able to start: a broken masquerade file is not a reason to take
the VPN down.
"""

from __future__ import annotations

import logging
import os
import stat
from collections.abc import Mapping
from pathlib import Path

log = logging.getLogger(__name__)

REQUIRED_ENV = ("TRAFFIC_STATS_SECRET", "ACME_DOMAIN", "ACME_EMAIL")
FRAGMENT_MARKER = "${MASQUERADE_YAML}"


def render(
    template: str,
    env: Mapping[str, str],
    masquerade_yaml: str = "",
) -> str:
    """Substitute the placeholders of the server template."""
    missing = [name for name in REQUIRED_ENV if not env.get(name)]
    if missing:
        raise ValueError(f"missing environment variables: {', '.join(missing)}")

    content = template
    for name in REQUIRED_ENV:
        content = content.replace("${" + name + "}", str(env[name]))
    if FRAGMENT_MARKER in content:
        content = content.replace(FRAGMENT_MARKER, masquerade_yaml.rstrip("\n"))
    return content


def validate_fragment_text(text: str) -> tuple[bool, str]:
    """Check that a fragment is YAML and only contains a valid masquerade block."""
    from .masquerade.render import validate_masquerade

    try:
        import yaml
    except ImportError:  # pragma: no cover - PyYAML is a hard requirement now
        return False, "PyYAML is not installed"

    try:
        payload = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        return False, f"fragment is not valid YAML: {exc}"
    if payload is None:
        return True, ""
    if not isinstance(payload, dict):
        return False, "fragment must be a YAML mapping"
    unknown = set(payload) - {"masquerade"}
    if unknown:
        return False, (
            "the masquerade fragment may only contain a 'masquerade' key, got "
            + ", ".join(sorted(unknown))
        )
    result = validate_masquerade(payload.get("masquerade"))
    if not result.ok:
        return False, "; ".join(result.errors)
    return True, ""


def read_fragment(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except OSError:
        return ""


def choose_fragment(
    primary: Path,
    last_good: Path,
) -> tuple[str, str]:
    """Return (fragment text, note) preferring a valid primary fragment."""
    notes: list[str] = []
    for label, path in (("configured", primary), ("last known-good", last_good)):
        text = read_fragment(path)
        if not text.strip():
            continue
        ok, error = validate_fragment_text(text)
        if ok:
            if notes:
                notes.append(f"using the {label} masquerade fragment")
            return text, "; ".join(notes)
        notes.append(f"{label} masquerade fragment ignored: {error}")
    if notes:
        notes.append("falling back to no masquerade section")
    return "", "; ".join(notes)


def atomic_write(path: Path, text: str, mode: int = 0o600) -> None:
    """Write ``text`` to ``path`` through a temporary file in the same directory."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    with open(tmp, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(text)
        handle.flush()
        os.fsync(handle.fileno())
    os.chmod(tmp, mode)
    os.replace(tmp, path)


def chown_if_root(path: Path, group: str | None = None) -> None:
    """Give a generated file root ownership and an optional group."""
    geteuid = getattr(os, "geteuid", None)
    if geteuid is None or geteuid() != 0 or not hasattr(os, "chown"):
        return
    gid = -1
    if group:
        try:  # pragma: no cover - only on the server
            import grp

            gid = grp.getgrnam(group).gr_gid
        except (ImportError, KeyError):  # pragma: no cover
            gid = -1
    try:  # pragma: no cover
        os.chown(path, 0, gid)
    except OSError as exc:  # pragma: no cover
        log.warning("could not chown %s: %s", path, exc)


def default_mode() -> int:
    return stat.S_IRUSR | stat.S_IWUSR
