#!/usr/bin/env python3
"""Render the Hysteria2 runtime configuration from the template.

usage: render_hysteria_config.py TEMPLATE OUTPUT

Placeholders come from the environment (``/etc/hyvpn/.env.hysteria``) except
the masquerade block, which is read from ``MASQUERADE_FILE``:

* ``${TRAFFIC_STATS_SECRET}``, ``${ACME_DOMAIN}``, ``${ACME_EMAIL}`` — required;
* ``${MASQUERADE_YAML}`` — replaced by the fragment, or by nothing when the
  variable is unset (an installation that does not manage masquerade).

A fragment that does not parse as YAML, or that contains anything other than a
valid ``masquerade`` block, is ignored in favour of ``MASQUERADE_LAST_GOOD``.
Starting the VPN always wins over serving a broken masquerade page.
"""

from __future__ import annotations

import os
import stat
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.hysteria_config import (  # noqa: E402
    REQUIRED_ENV,
    atomic_write,
    choose_fragment,
    render,
)


def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__.strip().splitlines()[2], file=sys.stderr)
        return 2

    template_path = Path(sys.argv[1])
    output = Path(sys.argv[2])

    missing = [name for name in REQUIRED_ENV if not os.environ.get(name)]
    if missing:
        print(f"missing environment variables: {', '.join(missing)}", file=sys.stderr)
        return 1

    try:
        template = template_path.read_text(encoding="utf-8")
    except OSError as exc:
        print(f"cannot read {template_path}: {exc}", file=sys.stderr)
        return 1

    fragment = ""
    fragment_file = os.environ.get("MASQUERADE_FILE")
    if fragment_file:
        last_good = os.environ.get("MASQUERADE_LAST_GOOD") or (
            fragment_file + ".last-good"
        )
        fragment, note = choose_fragment(Path(fragment_file), Path(last_good))
        if note:
            print(f"masquerade: {note}", file=sys.stderr)

    try:
        content = render(template, os.environ, fragment)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    output.parent.mkdir(parents=True, exist_ok=True)
    atomic_write(output, content, mode=stat.S_IRUSR | stat.S_IWUSR)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
