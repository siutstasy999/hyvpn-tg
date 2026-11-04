#!/usr/bin/env python3
from __future__ import annotations

import argparse
import asyncio
import json
import sys

from core.cert_service import get_cert_info
from core.config import get_settings
from core.db import connect
from core.hysteria_client import HysteriaStatsClient
from core.keys_service import (
    create_key,
    get_key,
    limit_of,
    list_keys,
    rename_key,
    reset_traffic,
    revoke_key,
    set_traffic_limit,
    used_bytes,
)
from core.masquerade import cli as masq_cli
from core.masquerade.models import EFFECTIVE_MODES
from core.stats_service import StatsService
from core.uri import build_uri

UNITS = ("B", "KB", "MB", "GB", "TB", "PB")
_UNIT_POWERS = {
    "": 3, "b": 0,
    "k": 1, "kb": 1, "kib": 1,
    "m": 2, "mb": 2, "mib": 2,
    "g": 3, "gb": 3, "gib": 3,
    "t": 4, "tb": 4, "tib": 4,
    "p": 5, "pb": 5, "pib": 5,
}


def fmt_bytes(size: float | int | None) -> str:
    value = float(size or 0)
    for index, unit in enumerate(UNITS):
        if abs(value) < 1024.0 or index == len(UNITS) - 1:
            return f"{value:.0f} {unit}" if index == 0 else f"{value:.2f} {unit}"
        value /= 1024.0
    return f"{value:.2f} PB"


def parse_size(raw: str) -> int:
    """Parse "50GB"/"500mb"/"0". A bare number means gigabytes."""
    text = raw.strip().lower().replace(" ", "")
    if text in {"0", "none", "off", "unlimited", "-"}:
        return 0

    digits = ""
    while text and (text[0].isdigit() or text[0] in ".,"):
        digits += text[0]
        text = text[1:]
    if not digits or text not in _UNIT_POWERS:
        raise argparse.ArgumentTypeError(
            f"invalid size: {raw!r} (examples: 50GB, 500mb, 0)"
        )
    return int(float(digits.replace(",", ".")) * (1024 ** _UNIT_POWERS[text]))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="hy-cli",
        description="Manage Hysteria2 VPN keys, quotas and statistics.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    create = sub.add_parser("create-key", help="issue a new key")
    create.add_argument("--label", required=True)
    create.add_argument("--tg-id", type=int)
    create.add_argument(
        "--limit",
        type=parse_size,
        default=0,
        metavar="SIZE",
        help="traffic quota, e.g. 50GB (0 = unlimited)",
    )

    revoke = sub.add_parser("revoke-key", help="revoke a key")
    revoke.add_argument("id")

    rename = sub.add_parser("rename-key", help="change a key label")
    rename.add_argument("id")
    rename.add_argument("label")

    limit = sub.add_parser("set-limit", help="set or clear a traffic quota")
    limit.add_argument("id")
    limit.add_argument("limit", type=parse_size, metavar="SIZE")

    reset = sub.add_parser("reset-traffic", help="zero the counters of a key")
    reset.add_argument("id")

    show = sub.add_parser("show", help="show one key with its connection URI")
    show.add_argument("id")
    show.add_argument("--uri-only", action="store_true")

    listing = sub.add_parser("list-keys", help="list keys")
    listing.add_argument("--active-only", action="store_true")
    listing.add_argument("--json", action="store_true")

    stats = sub.add_parser("stats", help="live traffic statistics")
    stats.add_argument("id", nargs="?")
    stats.add_argument("--all", action="store_true")

    sub.add_parser("cert", help="TLS certificate expiry")

    add_masquerade_parser(sub)

    return parser


def add_masquerade_parser(sub) -> None:
    masq = sub.add_parser(
        "masquerade",
        help="Hysteria2 masquerade: status, probes, upstream selection",
        description=(
            "Manage the Hysteria2 masquerade independently of TLS/SNI. "
            "See docs/MASQUERADE.md."
        ),
    )
    commands = masq.add_subparsers(dest="masq_command", required=True)

    status = commands.add_parser("status", help="show the active mode and upstream")
    status.add_argument("--json", action="store_true")

    check = commands.add_parser(
        "check", help="diagnose the current setup without changing anything"
    )
    check.add_argument("--json", action="store_true")

    doctor = commands.add_parser(
        "doctor", help="read-only report of the runtime environment"
    )
    doctor.add_argument("--json", action="store_true")

    init = commands.add_parser(
        "init", help="create masquerade.json and the local fallback site"
    )
    init.add_argument("--json", action="store_true")
    init.add_argument(
        "--no-restart",
        action="store_true",
        help="write the fragment without restarting Hysteria (used by install.sh)",
    )

    upgrade = commands.add_parser(
        "upgrade",
        help="inspect, recommend and (after confirmation) apply a masquerade setup",
    )
    upgrade.add_argument("--dry-run", action="store_true", help="print the plan only")
    upgrade.add_argument(
        "--read-only", action="store_true", help="run the diagnostics only"
    )
    upgrade.add_argument("-y", "--yes", action="store_true", help="no questions")
    upgrade.add_argument("--json", action="store_true")

    optimize = commands.add_parser(
        "optimize",
        help="select the best upstream (dry-run unless --apply is given)",
    )
    mode = optimize.add_mutually_exclusive_group()
    mode.add_argument("--dry-run", action="store_true", help="print the plan only")
    mode.add_argument(
        "--apply", action="store_true", help="apply after explicit confirmation"
    )
    optimize.add_argument("-y", "--yes", action="store_true", help="no questions")
    optimize.add_argument("--json", action="store_true")

    set_mode = commands.add_parser("set-mode", help="select the masquerade mode manually")
    set_mode.add_argument("mode", choices=["auto", *EFFECTIVE_MODES])
    set_mode.add_argument("--dry-run", action="store_true")
    set_mode.add_argument("-y", "--yes", action="store_true")
    set_mode.add_argument("--json", action="store_true")

    candidates = commands.add_parser("candidates", help="manage upstream candidates")
    cand = candidates.add_subparsers(dest="candidates_command", required=True)

    cand_list = cand.add_parser("list", help="list candidates and their health")
    cand_list.add_argument("--json", action="store_true")

    cand_test = cand.add_parser("test", help="probe every enabled candidate now")
    cand_test.add_argument("--json", action="store_true")

    cand_add = cand.add_parser("add", help="add an administrator-approved upstream")
    cand_add.add_argument("url")
    cand_add.add_argument("--id", help="candidate id (default: derived from the host)")
    cand_add.add_argument("--priority", type=int, default=0)
    cand_add.add_argument("--description", default="")
    cand_add.add_argument("--replace", action="store_true", help="overwrite an existing id")

    cand_remove = cand.add_parser("remove", help="remove a candidate")
    cand_remove.add_argument("id")

    for name, text in (("enable", "enable a candidate"), ("disable", "disable a candidate")):
        enable = cand.add_parser(name, help=text)
        enable.add_argument("id")

    apply_requests = commands.add_parser(
        "apply-requests",
        help="process requests queued by the bot (root worker, run by systemd)",
    )
    apply_requests.add_argument("--json", action="store_true")


async def cmd_create(args):
    settings = get_settings()
    db = await connect(settings.database_path)
    try:
        result = await create_key(
            db,
            args.label,
            args.tg_id,
            settings.server_domain,
            settings.server_port,
            args.limit,
            settings.profile_name,
        )
    finally:
        await db.close()

    print(f"id:       {result['id']}")
    print(f"label:    {result['label']}")
    print(f"limit:    {fmt_bytes(args.limit) if args.limit else 'unlimited'}")
    print(f"password: {result['password']}")
    print(f"uri:      {result['uri']}")


async def cmd_revoke(args):
    settings = get_settings()
    db = await connect(settings.database_path)
    try:
        ok = await revoke_key(db, args.id)
    finally:
        await db.close()
    if not ok:
        raise SystemExit(f"active key not found: {args.id}")
    print(f"revoked: {args.id}")


async def cmd_rename(args):
    settings = get_settings()
    db = await connect(settings.database_path)
    try:
        ok = await rename_key(db, args.id, args.label)
    finally:
        await db.close()
    if not ok:
        raise SystemExit(f"key not found: {args.id}")
    print(f"renamed: {args.id} -> {args.label}")


async def cmd_set_limit(args):
    settings = get_settings()
    db = await connect(settings.database_path)
    try:
        ok = await set_traffic_limit(db, args.id, args.limit)
    finally:
        await db.close()
    if not ok:
        raise SystemExit(f"key not found: {args.id}")
    if args.limit:
        print(f"limit: {args.id} -> {fmt_bytes(args.limit)}")
    else:
        print(f"limit removed: {args.id}")


async def cmd_reset_traffic(args):
    settings = get_settings()
    db = await connect(settings.database_path)
    try:
        ok = await reset_traffic(db, args.id)
    finally:
        await db.close()
    if not ok:
        raise SystemExit(f"key not found: {args.id}")
    print(f"traffic reset: {args.id}")


async def cmd_show(args):
    settings = get_settings()
    db = await connect(settings.database_path)
    try:
        row = await get_key(db, args.id)
    finally:
        await db.close()
    if row is None:
        raise SystemExit(f"key not found: {args.id}")

    uri = build_uri(
        row["password"],
        settings.server_domain,
        settings.server_port,
        settings.profile_name,
    )
    if args.uri_only:
        print(uri)
        return

    limit = limit_of(row)
    print(f"id:        {row['id']}")
    print(f"label:     {row['label']}")
    print(f"active:    {'yes' if row['is_active'] else 'no'}")
    print(f"created:   {row['created_at']}")
    print(f"last_seen: {row['last_seen_at'] or '-'}")
    print(f"upload:    {fmt_bytes(row['upload_total'])}")
    print(f"download:  {fmt_bytes(row['download_total'])}")
    print(f"used:      {fmt_bytes(used_bytes(row))}")
    print(f"limit:     {fmt_bytes(limit) if limit else 'unlimited'}")
    print(f"uri:       {uri}")


async def cmd_list(args):
    settings = get_settings()
    db = await connect(settings.database_path)
    try:
        rows = await list_keys(db, args.active_only)
    finally:
        await db.close()

    if args.json:
        print(
            json.dumps(
                [dict(row) for row in rows], ensure_ascii=False, indent=2, default=str
            )
        )
        return

    for row in rows:
        limit = limit_of(row)
        used = used_bytes(row)
        if not row["is_active"]:
            state = "revoked"
        elif limit and used >= limit:
            state = "blocked"
        else:
            state = "active"
        quota = f"/{fmt_bytes(limit)}" if limit else ""
        print(
            f"{row['id']}  {state:7}  {row['label']}  "
            f"used={fmt_bytes(used)}{quota}  "
            f"last_seen={row['last_seen_at'] or '-'}"
        )


async def make_stats_service():
    settings = get_settings()
    client = HysteriaStatsClient(settings.stats_url, settings.hysteria_stats_secret)
    return settings, StatsService(
        settings.database_path,
        client,
        settings.poll_interval_seconds,
        settings.flush_interval_seconds,
    )


async def cmd_stats(args):
    if not args.id and not args.all:
        raise SystemExit("provide <id> or --all")

    settings, service = await make_stats_service()

    if args.all:
        db = await connect(settings.database_path)
        try:
            rows = await list_keys(db, active_only=False)
        finally:
            await db.close()

        results = []
        for row in rows:
            try:
                results.append(await service.get_live_stats(row["id"]))
            except Exception as exc:
                results.append({"id": row["id"], "error": str(exc)})
        print(json.dumps(results, ensure_ascii=False, indent=2))
        return

    try:
        result = await service.get_live_stats(args.id)
    except KeyError as exc:
        raise SystemExit(f"key not found: {args.id}") from exc
    print(json.dumps(result, ensure_ascii=False, indent=2))


def masquerade_context(args) -> masq_cli.Context:
    settings = get_settings()
    return masq_cli.Context(
        paths=settings.masq_paths,
        domain=settings.server_domain,
        server_port=settings.server_port,
        acme_dir=settings.acme_dir,
        cert_status_path=settings.cert_status_path,
        json_output=bool(getattr(args, "json", False)),
        assume_yes=bool(getattr(args, "yes", False)),
        interactive=sys.stdin.isatty() and sys.stdout.isatty(),
    )


def run_masquerade(args) -> int:
    ctx = masquerade_context(args)
    command = args.masq_command
    if command == "status":
        return masq_cli.cmd_status(ctx)
    if command == "check":
        return masq_cli.cmd_check(ctx)
    if command == "doctor":
        return masq_cli.cmd_doctor(ctx)
    if command == "init":
        return masq_cli.cmd_init(ctx, args)
    if command == "upgrade":
        return masq_cli.cmd_upgrade(ctx, args)
    if command == "optimize":
        return masq_cli.cmd_optimize(ctx, args)
    if command == "set-mode":
        return masq_cli.cmd_set_mode(ctx, args)
    if command == "apply-requests":
        return masq_cli.cmd_apply_requests(ctx)
    if command == "candidates":
        sub = args.candidates_command
        if sub == "list":
            return masq_cli.cmd_candidates_list(ctx)
        if sub == "test":
            return masq_cli.cmd_candidates_test(ctx)
        if sub == "add":
            return masq_cli.cmd_candidates_add(ctx, args)
        if sub == "remove":
            return masq_cli.cmd_candidates_remove(ctx, args)
        if sub == "enable":
            return masq_cli.cmd_candidates_enable(ctx, args, True)
        if sub == "disable":
            return masq_cli.cmd_candidates_enable(ctx, args, False)
    raise SystemExit(f"unknown masquerade command: {command}")


async def cmd_masquerade(args):
    raise SystemExit(run_masquerade(args))


async def cmd_cert(_args):
    settings = get_settings()
    info = get_cert_info(
        settings.server_domain, settings.acme_dir, settings.cert_status_path
    )
    if not info.known:
        raise SystemExit(f"certificate state unknown: {info.error}")
    print(f"domain:     {info.domain}")
    print(f"issuer:     {info.issuer or '-'}")
    print(f"not_after:  {info.not_after}")
    print(f"days_left:  {info.days_left}")
    print(f"source:     {info.source}")


HANDLERS = {
    "create-key": cmd_create,
    "revoke-key": cmd_revoke,
    "rename-key": cmd_rename,
    "set-limit": cmd_set_limit,
    "reset-traffic": cmd_reset_traffic,
    "show": cmd_show,
    "list-keys": cmd_list,
    "stats": cmd_stats,
    "cert": cmd_cert,
    "masquerade": cmd_masquerade,
}


async def main():
    args = build_parser().parse_args()
    await HANDLERS[args.command](args)


if __name__ == "__main__":
    asyncio.run(main())
