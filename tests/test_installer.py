"""Tests for the bash helpers inside install.sh.

The script is sourced with its `main "$@"` line stripped, so individual
functions can be called without running an installation.
"""

import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

BASH = shutil.which("bash")
ROOT = Path(__file__).resolve().parent.parent

pytestmark = pytest.mark.skipif(BASH is None, reason="bash is not available")


def run_snippet(snippet: str, env_setup: str = "") -> str:
    """Source install.sh and run `snippet`, returning stdout."""
    script = (ROOT / "install.sh").read_text(encoding="utf-8")
    sourceable = script.replace('\nmain "$@"\n', "\n")
    assert sourceable != script, "could not strip the main call"

    with tempfile.TemporaryDirectory() as td:
        lib = Path(td) / "lib.sh"
        lib.write_text(sourceable, encoding="utf-8", newline="\n")
        runner = Path(td) / "run.sh"
        runner.write_text(
            f'source "{lib.as_posix()}"\n{env_setup}\n{snippet}\n',
            encoding="utf-8",
            newline="\n",
        )
        result = subprocess.run(
            [BASH, runner.as_posix()],
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=60,
        )
    assert result.returncode == 0, result.stderr
    return result.stdout


def test_syntax_is_valid():
    for script in ("install.sh", "bin/hyvpn"):
        result = subprocess.run(
            [BASH, "-n", (ROOT / script).as_posix()], capture_output=True, text=True
        )
        assert result.returncode == 0, f"{script}: {result.stderr}"


def test_flag_of_builds_regional_indicators():
    out = run_snippet('flag_of FI; echo; flag_of nl; echo; flag_of US; echo')
    flags = out.splitlines()
    assert flags[0] == "\U0001F1EB\U0001F1EE"  # FI
    assert flags[1] == "\U0001F1F3\U0001F1F1"  # nl, lower case accepted
    assert flags[2] == "\U0001F1FA\U0001F1F8"  # US


def test_flag_of_rejects_junk():
    out = run_snippet('if flag_of "1X"; then echo BAD; else echo rejected; fi')
    assert out.strip() == "rejected"


def test_country_name_known_and_unknown():
    out = run_snippet(
        'country_name FI; country_name nl; country_name GB; country_name ZZ'
    )
    assert out.split("\n")[:4] == ["Finland", "Netherlands", "United Kingdom", "ZZ"]


def test_suggested_location_reads_like_a_profile_name():
    out = run_snippet("suggest_location FI").strip()
    assert out == "Hysteria2 Finland \U0001F1EB\U0001F1EE"


def test_explicit_location_wins_over_detection():
    out = run_snippet("default_location", env_setup='LOCATION="My Server"')
    assert out.strip() == "My Server"


def test_location_falls_back_to_the_domain_without_detection():
    # dry-run keeps the network out of it, which is also how CI runs.
    out = run_snippet(
        "default_location", env_setup='LOCATION=""; DRY_RUN=yes; DOMAIN="vpn.example.com"'
    )
    assert out.strip() == "vpn.example.com"


def test_validators():
    checks = {
        "valid_domain vpn.example.com": True,
        "valid_domain my-own.online": True,
        "valid_domain not_a_domain": False,
        "valid_domain localhost": False,
        "valid_email a@b.co": True,
        "valid_email nope": False,
        'valid_token "123456789:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw"': True,
        'valid_token "123456789:TEST-TOKEN-NOT-A-REAL-BOT-TOKEN"': True,
        'valid_token "abc:def"': False,
        'valid_ids "123"': True,
        'valid_ids "123, 456"': True,
        'valid_ids "abc"': False,
        "valid_port 443": True,
        "valid_port 70000": False,
    }
    snippet = "\n".join(
        f'if {check}; then echo "yes"; else echo "no"; fi' for check in checks
    )
    results = run_snippet(snippet).split()
    assert results == ["yes" if expected else "no" for expected in checks.values()]


def test_env_value_reads_the_last_definition():
    with tempfile.TemporaryDirectory() as td:
        env_file = Path(td) / ".env"
        env_file.write_text(
            "A=1\nSERVER_DOMAIN=first.example\nB=2\nSERVER_DOMAIN=second.example\n",
            encoding="utf-8",
            newline="\n",
        )
        out = run_snippet(
            f'env_value "{env_file.as_posix()}" SERVER_DOMAIN; '
            f'echo "[$(env_value "{env_file.as_posix()}" MISSING)]"'
        )
    assert out.splitlines() == ["second.example", "[]"]


def test_help_exits_cleanly():
    result = subprocess.run(
        [BASH, (ROOT / "install.sh").as_posix(), "--help"],
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    assert result.returncode == 0
    assert "--dry-run" in result.stdout
    assert "--domain" in result.stdout


def test_unknown_flag_fails_loudly():
    result = subprocess.run(
        [BASH, (ROOT / "install.sh").as_posix(), "--nope"],
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    assert result.returncode != 0
    assert "unknown option" in result.stderr


def test_upgrade_keeps_a_name_the_operator_chose():
    out = run_snippet(
        "default_location",
        env_setup='LOCATION=""; DRY_RUN=yes; DOMAIN="vpn.example.com"; '
        'PREV_LOCATION="My own server"',
    )
    assert out.strip() == "My own server"


def test_upgrade_replaces_a_name_that_was_only_the_domain():
    # The old fallback was the domain itself; that is not a real choice, so it
    # must not block the region suggestion. Without network (dry-run) the
    # domain stays.
    out = run_snippet(
        "default_location",
        env_setup='LOCATION=""; DRY_RUN=yes; DOMAIN="vpn.example.com"; '
        'PREV_LOCATION="vpn.example.com"',
    )
    assert out.strip() == "vpn.example.com"


def test_non_interactive_upgrade_keeps_every_previous_answer():
    out = run_snippet(
        'echo "$DOMAIN|$EMAIL|$ADMIN_IDS|$PORT|$LANG_CHOICE|$LOCATION"',
        env_setup=(
            'ASSUME_YES=yes; DRY_RUN=yes; '
            'PREV_DOMAIN="old.example"; PREV_EMAIL="old@example.com"; '
            'PREV_IDS="777"; PREV_PORT="8443"; PREV_LANG="en"; '
            'PREV_LOCATION="Old name"; '
            'BOT_TOKEN="123456789:TEST-TOKEN-NOT-A-REAL-BOT-TOKEN"; '
            "ask_everything"
        ),
    )
    assert out.strip() == "old.example|old@example.com|777|8443|en|Old name"


def test_fresh_non_interactive_install_uses_the_documented_defaults():
    out = run_snippet(
        'echo "$EMAIL|$PORT|$LANG_CHOICE|$LOCATION"',
        env_setup=(
            'ASSUME_YES=yes; DRY_RUN=yes; DOMAIN="vpn.example.com"; '
            'ADMIN_IDS="1"; '
            'BOT_TOKEN="123456789:TEST-TOKEN-NOT-A-REAL-BOT-TOKEN"; '
            "ask_everything"
        ),
    )
    assert out.strip() == "admin@vpn.example.com|443|ru|vpn.example.com"
