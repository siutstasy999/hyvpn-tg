"""The local fallback website.

When no upstream passes validation the server still has to look like a normal
website to anyone who connects to the port without credentials. Serving an
empty directory (Hysteria2 would answer 404 for every path) or a single word is
worse than serving nothing, because it is a fingerprint of a misconfigured
proxy.

The pages are stored as templates in ``core/masquerade/site`` and materialised
into the configured site directory with the administrator's own domain. They
use no external fonts, scripts, images or CDNs, so the fallback keeps working
on a server with no outbound connectivity at all.
"""

from __future__ import annotations

import os
import re
from datetime import datetime, timezone
from pathlib import Path

SITE_SOURCE = Path(__file__).resolve().parent / "site"
SITE_FILES = ("index.html", "404.html", "style.css", "favicon.svg")
DEFAULT_INDEX = "index.html"

_DOMAIN_RE = re.compile(r"[^A-Za-z0-9.-]")


def initials_for(domain: str) -> str:
    """Two-letter mark for the header: "vpn.example.com" -> "VE"."""
    label = (domain or "").split(".", 1)[0]
    letters = [char for char in label if char.isalnum()]
    if not letters:
        return "HY"
    if len(letters) == 1:
        return letters[0].upper() * 2
    return (letters[0] + letters[1]).upper()


def render_site(domain: str, *, year: int | None = None) -> dict[str, bytes]:
    """Return {filename: content} for the fallback site of ``domain``."""
    safe_domain = _DOMAIN_RE.sub("", domain or "") or "localhost"
    stamp = str(year if year is not None else datetime.now(timezone.utc).year)
    replacements = {
        "{{DOMAIN}}": safe_domain,
        "{{YEAR}}": stamp,
        "{{INITIALS}}": initials_for(safe_domain),
    }
    files: dict[str, bytes] = {}
    for name in SITE_FILES:
        source = SITE_SOURCE / name
        text = source.read_text(encoding="utf-8")
        for token, value in replacements.items():
            text = text.replace(token, value)
        files[name] = text.encode("utf-8")
    return files


def materialize(
    dest: Path,
    *,
    domain: str,
    year: int | None = None,
    owner: str = "hyvpn",
    group: str = "hyvpn",
) -> list[str]:
    """Write the site into ``dest``, touching only files whose content changed.

    Returns the list of filenames that were (re)written, which makes the caller
    able to report whether anything actually changed.
    """
    rendered = render_site(domain, year=year)
    dest.mkdir(parents=True, exist_ok=True)
    changed: list[str] = []
    for name, payload in rendered.items():
        target = dest / name
        try:
            if target.is_file() and target.read_bytes() == payload:
                continue
        except OSError:
            pass
        tmp = target.with_name(target.name + ".tmp")
        with open(tmp, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp, 0o644)
        os.replace(tmp, target)
        _chown(target, owner, group)
        changed.append(name)
    return changed


def _chown(path: Path, owner: str, group: str) -> None:
    geteuid = getattr(os, "geteuid", None)
    if geteuid is None or geteuid() != 0 or not hasattr(os, "chown"):
        return
    try:  # pragma: no cover - only on the server
        import grp
        import pwd

        uid = pwd.getpwnam(owner).pw_uid
        gid = grp.getgrnam(group).gr_gid
    except (ImportError, KeyError):  # pragma: no cover
        return
    try:  # pragma: no cover
        os.chown(path, uid, gid)
    except OSError:  # pragma: no cover
        pass


def is_current(dest: Path, domain: str) -> bool:
    """True when ``dest`` already holds the site for ``domain``."""
    if not (dest / DEFAULT_INDEX).is_file():
        return False
    try:
        rendered = render_site(domain)
    except OSError:  # pragma: no cover - templates are shipped with the code
        return False
    for name, payload in rendered.items():
        target = dest / name
        try:
            if not target.is_file() or target.read_bytes() != payload:
                return False
        except OSError:
            return False
    return True
