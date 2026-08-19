#!/usr/bin/env python3
from __future__ import annotations

import os
import stat
import sys
from pathlib import Path

REQUIRED = ("TRAFFIC_STATS_SECRET", "ACME_DOMAIN", "ACME_EMAIL")


def main() -> None:
    if len(sys.argv) != 3:
        raise SystemExit("usage: render_hysteria_config.py TEMPLATE OUTPUT")

    template = Path(sys.argv[1])
    output = Path(sys.argv[2])

    missing = [name for name in REQUIRED if not os.environ.get(name)]
    if missing:
        raise SystemExit(f"missing environment variables: {', '.join(missing)}")

    content = template.read_text(encoding="utf-8")
    for name in REQUIRED:
        content = content.replace("${" + name + "}", os.environ[name])

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(content, encoding="utf-8")
    os.chmod(output, stat.S_IRUSR | stat.S_IWUSR)


if __name__ == "__main__":
    main()
