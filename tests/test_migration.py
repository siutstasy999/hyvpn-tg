"""Tests for the migration bundle: install.sh --export / --import-bundle.

The export half is a self-contained bash script that runs on any server, so it
is exercised directly: a fake /var/lib/hyvpn tree is built in a temp directory
and the script is run against it through the HYVPN_DATA_DIR / HYVPN_CONF_DIR /
HYVPN_ACME_DIR overrides.
"""

import io
import os
import shutil
import sqlite3
import subprocess
import tarfile
import tempfile
from pathlib import Path

import pytest

from core.db import SCHEMA

BASH = shutil.which("bash")
ROOT = Path(__file__).resolve().parent.parent


def sql_tool_works() -> bool:
    """The exporter needs sqlite3 or python3 *that actually runs*."""
    if BASH is None:
        return False
    if shutil.which("sqlite3"):
        return True
    probe = subprocess.run(
        [BASH, "-c", "python3 -c 'import sqlite3' 2>/dev/null"],
        capture_output=True,
    )
    return probe.returncode == 0


pytestmark = [
    pytest.mark.skipif(BASH is None, reason="bash is not available"),
    pytest.mark.skipif(not sql_tool_works(), reason="sqlite3/python3 not usable from bash"),
]

BOT_TOKEN = "123456789:TEST-TOKEN-NOT-A-REAL-BOT-TOKEN"


def posix(path: Path) -> str:
    return str(path).replace("\\", "/")


def source_snippet(snippet: str) -> str:
    """Source install.sh (without its main call) and run `snippet`."""
    script = (ROOT / "install.sh").read_text(encoding="utf-8")
    sourceable = script.replace('\nmain "$@"\n', "\n")
    assert sourceable != script, "could not strip the main call"

    with tempfile.TemporaryDirectory() as td:
        lib = Path(td) / "lib.sh"
        lib.write_text(sourceable, encoding="utf-8", newline="\n")
        runner = Path(td) / "run.sh"
        runner.write_text(
            f'source "{posix(lib)}"\n{snippet}\n', encoding="utf-8", newline="\n"
        )
        result = subprocess.run(
            [BASH, posix(runner)],
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=60,
        )
    assert result.returncode == 0, result.stderr
    return result.stdout


def exporter_source() -> str:
    return source_snippet("export_script_source")


def make_source_tree(root: Path, keys: int = 3, active: int = 2) -> tuple[Path, Path, Path]:
    """A fake /var/lib/hyvpn, /etc/hyvpn and ACME directory."""
    data = root / "data"
    conf = root / "conf"
    acme = root / "acme"
    for path in (data, conf, acme):
        path.mkdir(parents=True)

    db = sqlite3.connect(data / "hyvpn.sqlite3")
    try:
        db.executescript(SCHEMA)
        for index in range(keys):
            db.execute(
                """
                INSERT INTO keys (id, label, password, is_active, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    f"id-{index}",
                    f"key {index}",
                    f"secret-{index}",
                    1 if index >= keys - active else 0,
                    f"2026-10-26T00:00:0{index}+00:00",
                ),
            )
        db.commit()
    finally:
        db.close()

    (conf / ".env.core").write_text(
        "SERVER_DOMAIN=vpn.example.com\n"
        "SERVER_PORT=443\n"
        "LOCATION_NAME=Hysteria2 Finland \U0001F1EB\U0001F1EE\n",
        encoding="utf-8",
    )
    (conf / ".env.bot").write_text(
        f"BOT_TOKEN={BOT_TOKEN}\nALLOWED_TG_IDS=777\nDEFAULT_LANG=ru\n",
        encoding="utf-8",
    )
    (conf / ".env.hysteria").write_text(
        "TRAFFIC_STATS_SECRET=secret\nACME_EMAIL=admin@example.com\n",
        encoding="utf-8",
    )
    (acme / "vpn.example.com.crt").write_text("cert", encoding="utf-8")
    (acme / "vpn.example.com.key").write_text("key", encoding="utf-8")
    return data, conf, acme


def run_exporter(root: Path, target: str | None, with_acme: bool = True):
    data, conf, acme = make_source_tree(root)
    script = root / "export.sh"
    script.write_text(exporter_source(), encoding="utf-8", newline="\n")

    env = os.environ.copy()
    env.update(
        HYVPN_DATA_DIR=posix(data),
        HYVPN_CONF_DIR=posix(conf),
        HYVPN_ACME_DIR=posix(acme) if with_acme else posix(root / "missing-acme"),
    )
    args = [BASH, posix(script)]
    if target is not None:
        args.append(target)
    return subprocess.run(args, env=env, capture_output=True, timeout=120)


def test_bundle_contains_database_configuration_and_manifest(tmp_path):
    archive = tmp_path / "bundle.tar.gz"
    result = run_exporter(tmp_path, posix(archive))
    assert result.returncode == 0, result.stderr.decode()
    assert archive.is_file()

    with tarfile.open(archive) as tar:
        names = set(tar.getnames())
        assert {"MANIFEST", "hyvpn.sqlite3", "env/core.env", "env/bot.env"} <= names
        assert "acme" in names

        manifest = tar.extractfile("MANIFEST").read().decode()
        assert "format=1" in manifest
        assert "domain=vpn.example.com" in manifest
        assert "port=443" in manifest
        assert "keys_total=3" in manifest
        assert "keys_active=2" in manifest

        database = tmp_path / "unpacked.sqlite3"
        database.write_bytes(tar.extractfile("hyvpn.sqlite3").read())

    assert database.read_bytes()[:16] == b"SQLite format 3\x00"
    con = sqlite3.connect(database)
    try:
        assert con.execute("SELECT COUNT(*) FROM keys").fetchone()[0] == 3
    finally:
        con.close()


def test_bundle_without_acme_directory_still_builds(tmp_path):
    archive = tmp_path / "bundle.tar.gz"
    result = run_exporter(tmp_path, posix(archive), with_acme=False)
    assert result.returncode == 0, result.stderr.decode()
    with tarfile.open(archive) as tar:
        assert "acme" not in tar.getnames()


def test_exporter_streams_the_archive_to_stdout(tmp_path):
    result = run_exporter(tmp_path, None)
    assert result.returncode == 0, result.stderr.decode()
    with tarfile.open(fileobj=io.BytesIO(result.stdout)) as tar:
        assert "hyvpn.sqlite3" in tar.getnames()


def test_exporter_refuses_when_there_is_no_database(tmp_path):
    data = tmp_path / "empty"
    data.mkdir()
    script = tmp_path / "export.sh"
    script.write_text(exporter_source(), encoding="utf-8", newline="\n")
    env = os.environ.copy()
    env.update(HYVPN_DATA_DIR=posix(data), HYVPN_CONF_DIR=posix(data))
    result = subprocess.run(
        [BASH, posix(script), posix(tmp_path / "x.tar.gz")],
        env=env,
        capture_output=True,
        timeout=60,
    )
    assert result.returncode != 0
    assert b"database not found" in result.stderr


def test_import_reads_the_bundle_and_fills_the_answers(tmp_path):
    archive = tmp_path / "bundle.tar.gz"
    assert run_exporter(tmp_path, posix(archive)).returncode == 0

    out = source_snippet(
        "MIGRATE_DIR=''\n"
        f'migrate_load_bundle "{posix(archive)}"\n'
        "migrate_prefill\n"
        "printf '%s|%s|%s|%s|%s|%s\\n' \"$IMPORT_KEYS_TOTAL\" \"$IMPORT_KEYS_ACTIVE\" "
        "\"$PREV_DOMAIN\" \"$PREV_PORT\" \"$PREV_LOCATION\" \"$PREV_IDS\""
    )
    last = out.strip().splitlines()[-1]
    assert last == "3|2|vpn.example.com|443|Hysteria2 Finland \U0001F1EB\U0001F1EE|777"


def test_import_rejects_a_broken_archive(tmp_path):
    bogus = tmp_path / "bogus.tar.gz"
    bogus.write_bytes(b"not a tar archive at all")
    result = subprocess.run(
        [
            BASH,
            "-c",
            "MIGRATE_DIR=''; source \"$1\"; migrate_load_bundle \"$2\"",
            "bash",
            posix(_write_library(tmp_path)),
            posix(bogus),
        ],
        capture_output=True,
        timeout=60,
    )
    assert result.returncode != 0
    assert "hyvpn-migrate" in result.stderr.decode("utf-8")


def _write_library(directory: Path) -> Path:
    """install.sh with main stripped, for tests that expect a failure exit."""
    script = (ROOT / "install.sh").read_text(encoding="utf-8")
    lib = directory / "lib.sh"
    lib.write_text(script.replace('\nmain "$@"\n', "\n"), encoding="utf-8", newline="\n")
    return lib


def test_help_lists_the_migration_flags():
    result = subprocess.run(
        [BASH, posix(ROOT / "install.sh"), "--help"],
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    assert result.returncode == 0
    for flag in ("--export", "--import-bundle", "--import HOST", "--import-password"):
        assert flag in result.stdout


def test_flags_parse_into_the_migration_variables():
    out = source_snippet(
        "parse_args --import old.example.net --import-user deploy --import-password "
        "--import-ssh-port 2222\n"
        "printf '%s|%s|%s|%s|%s\\n' \"$IMPORT_HOST\" \"$IMPORT_USER\" \"$IMPORT_AUTH\" "
        "\"$IMPORT_SSH_PORT\" \"$IMPORT_MODE\""
    )
    assert out.strip().splitlines()[-1] == "old.example.net|deploy|password|2222|"

    out = source_snippet(
        "parse_args --import-bundle /tmp/x.tar.gz\n"
        "migrate_decide\n"
        "printf '%s|%s\\n' \"$IMPORT_MODE\" \"$IMPORT_BUNDLE\""
    )
    assert out.strip().splitlines()[-1] == "bundle|/tmp/x.tar.gz"
