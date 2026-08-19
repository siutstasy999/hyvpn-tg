#!/usr/bin/env python3
"""Write a readable snapshot of the TLS certificate state.

Run as root by hy-certwatch.service: the ACME directory belongs to the
``hysteria`` user, while hy-bot and hy-core run as ``hyvpn`` and only read the
resulting JSON file.

usage: cert_probe.py DOMAIN [ACME_DIR] [OUTPUT]
"""

from __future__ import annotations

import os
import stat
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.cert_service import (  # noqa: E402
    DEFAULT_ACME_DIR,
    DEFAULT_STATUS_PATH,
    MISSING,
    CertInfo,
    find_cert_file,
    read_cert_file,
)


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__.strip(), file=sys.stderr)
        return 2

    domain = sys.argv[1]
    acme_dir = sys.argv[2] if len(sys.argv) > 2 else DEFAULT_ACME_DIR
    output = Path(sys.argv[3] if len(sys.argv) > 3 else DEFAULT_STATUS_PATH)

    cert_file = find_cert_file(domain, acme_dir)
    if cert_file is None:
        info = CertInfo(
            domain=domain,
            source="file",
            error=f"not issued yet: no certificate for {domain} under {acme_dir}",
            state=MISSING,
        )
    else:
        info = read_cert_file(domain, cert_file)

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(info.to_json() + "\n", encoding="utf-8")
    os.chmod(output, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH)

    if info.known:
        print(f"{domain}: valid until {info.not_after} ({info.days_left} days left)")
        return 0
    print(f"{domain}: unknown ({info.error})", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
