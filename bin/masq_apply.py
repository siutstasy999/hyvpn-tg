#!/usr/bin/env python3
"""Execute masquerade requests queued by the Telegram bot.

Started by ``hy-masqapply.path`` when the bot drops a request file into
``/var/lib/hyvpn/masquerade/requests``. Runs as root, because applying a
configuration restarts a systemd unit and writes ``/etc/hyvpn``.

The request format is fixed (see ``core/masquerade/requests.py``); there is no
way to pass a shell command through it.

usage: masq_apply.py [--json]
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.config import get_settings  # noqa: E402
from core.masquerade import cli  # noqa: E402

log = logging.getLogger("masq-apply")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--json", action="store_true", help="print a JSON report")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
    )

    settings = get_settings()
    context = cli.Context(
        paths=settings.masq_paths,
        domain=settings.server_domain,
        server_port=settings.server_port,
        acme_dir=settings.acme_dir,
        cert_status_path=settings.cert_status_path,
        json_output=args.json,
        assume_yes=True,  # the request itself is the authorisation
        interactive=False,
        out=print if not args.json else (lambda text: None),
    )
    try:
        code = cli.cmd_apply_requests(context)
    except Exception as exc:  # noqa: BLE001 - the unit must log, not hang
        log.exception("could not process requests: %s", exc)
        return 1
    if args.json:
        print(json.dumps({"exit_code": code}, ensure_ascii=False))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
