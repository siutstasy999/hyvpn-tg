"""Building and naming hysteria2:// URIs.

The fragment is what VPN clients show as the profile name, so it stays
human-readable UTF-8 instead of percent-encoded bytes: a name like
``🇫🇮 Finland`` must not turn into ``%F0%9F%87%AB%F0%9F%87%AE%20Finland``.
Only the password is percent-encoded, because it is credential material and
may contain reserved characters.
"""

from __future__ import annotations

import unicodedata
from urllib.parse import quote

MAX_NAME = 64


def clean_name(raw: str | None) -> str:
    """Normalise a profile name: no control characters, single spaces."""
    if not raw:
        return ""
    # Control characters become spaces rather than vanishing, so a name with
    # a newline in it reads as two words instead of one glued-together word.
    text = "".join(
        " " if unicodedata.category(char)[0] == "C" else char for char in str(raw)
    )
    return " ".join(text.split())[:MAX_NAME].strip()


def build_uri(
    password: str,
    domain: str,
    port: int = 443,
    name: str = "",
) -> str:
    """Return the hysteria2:// URI for a key.

    ``name`` is the profile name shown by the client; it is intentionally the
    server location, not the key label, so the same server looks the same in
    every client. Falls back to the domain when empty.
    """
    base = (
        f"hysteria2://{quote(password, safe='')}@{domain}:{port}"
        f"/?sni={domain}"
    )
    fragment = clean_name(name) or domain
    return f"{base}#{fragment}"
