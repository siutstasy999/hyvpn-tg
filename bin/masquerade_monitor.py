#!/usr/bin/env python3
"""Background health monitor for the Hysteria2 masquerade.

Run by ``hy-masqwatch.timer`` every 15 minutes as root. One cycle:

1. probe the active upstream and the configured alternatives;
2. score them and decide whether anything should change;
3. deploy only when the effective configuration really changes;
4. write the decision to the log and to the state file.

The unit is a ``oneshot`` with a timer, not a daemon: if a cycle hangs, systemd
stops it, and there is no long-lived process to keep alive.

usage: masquerade_monitor.py [--dry-run] [--json]
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.config import get_settings  # noqa: E402
from core.masquerade.engine import MasqueradeEngine  # noqa: E402

log = logging.getLogger("masq-monitor")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="probe and decide, but do not write the configuration",
    )
    parser.add_argument("--json", action="store_true", help="print a JSON report")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
    )

    settings = get_settings()
    engine = MasqueradeEngine(
        settings.masq_paths,
        domain=settings.server_domain,
        server_port=settings.server_port,
        acme_dir=settings.acme_dir,
        cert_status_path=settings.cert_status_path,
    )

    try:
        report = engine.cycle(apply=not args.dry_run, dry_run=args.dry_run)
    except Exception as exc:  # noqa: BLE001 - the timer must log, not crash
        log.exception("masquerade cycle failed: %s", exc)
        return 1

    if args.json:
        print(json.dumps(report.to_json(), ensure_ascii=False, indent=2))
    else:
        deployment = report.deployment
        log.info(
            "masquerade: %s -> %s (%s)",
            report.mode_before,
            report.plan.mode,
            report.plan.candidate_id or "local fallback",
        )
        log.info("decision: %s", report.plan.reason)
        for evaluation in report.plan.evaluations:
            log.info(
                "candidate %s: %s score=%.2f latency=%.0fms samples=%d",
                evaluation.candidate_id,
                evaluation.health,
                evaluation.score,
                evaluation.mean_latency_ms,
                evaluation.samples,
            )
        if deployment is not None:
            if deployment.changed and deployment.applied:
                state = (
                    "rolled back"
                    if deployment.rolled_back
                    else "applied"
                    if deployment.verified
                    else "applied, unverified"
                )
                log.info("deployment: %s (backup %s)", state, deployment.backup)
            elif deployment.changed:
                log.info("deployment: not applied")
            else:
                log.info("deployment: configuration unchanged, service untouched")
            for note in deployment.notes:
                log.debug("note: %s", note)
            for error in deployment.errors:
                log.error("deployment error: %s", error)
        for error in report.errors:
            log.error("error: %s", error)

    if report.deployment is not None and (
        report.deployment.rolled_back or report.deployment.errors
    ):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
