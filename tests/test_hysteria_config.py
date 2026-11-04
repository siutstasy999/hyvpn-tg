"""The runtime renderer: substitution, fragment injection, safe fallback."""

from __future__ import annotations

import os
import subprocess
import sys

import pytest

from core.hysteria_config import (
    choose_fragment,
    read_fragment,
    render,
    validate_fragment_text,
)
from tests.masq_fakes import TEMPLATE

ENV = {
    "ACME_DOMAIN": "vpn.example.com",
    "ACME_EMAIL": "admin@example.com",
    "TRAFFIC_STATS_SECRET": "s3cret",
}
FRAGMENT = (
    "masquerade:\n"
    "  type: file\n"
    "  file:\n"
    "    dir: /var/lib/hyvpn/masquerade/site\n"
)


def test_placeholders_are_substituted():
    text = render(TEMPLATE, ENV, FRAGMENT)
    assert "${ACME_DOMAIN}" not in text
    assert "vpn.example.com" in text
    assert "secret: s3cret" in text
    assert FRAGMENT.strip() in text


def test_missing_environment_variable_is_an_error():
    with pytest.raises(ValueError) as excinfo:
        render(TEMPLATE, {k: v for k, v in ENV.items() if k != "ACME_EMAIL"})
    assert "ACME_EMAIL" in str(excinfo.value)


def test_empty_fragment_renders_without_a_masquerade_section():
    text = render(TEMPLATE, ENV, "")
    assert "masquerade" not in text
    assert "listen: :443" in text


def test_fragment_validation_accepts_a_masquerade_block():
    ok, error = validate_fragment_text(FRAGMENT)
    assert ok, error


def test_fragment_validation_rejects_other_top_level_keys():
    ok, error = validate_fragment_text("masquerade:\n  type: file\n  file:\n    dir: /tmp\n"
                                       "tls:\n  insecure: true\n")
    assert not ok
    assert "masquerade" in error


def test_fragment_validation_rejects_broken_yaml():
    ok, error = validate_fragment_text("masquerade: [unclosed")
    assert not ok
    assert "YAML" in error


def test_fragment_validation_rejects_insecure_proxy():
    ok, error = validate_fragment_text(
        "masquerade:\n  type: proxy\n  proxy:\n"
        "    url: https://example.com/\n    insecure: true\n"
    )
    assert not ok
    assert "insecure" in error


def test_choose_fragment_prefers_a_valid_primary(tmp_path):
    primary = tmp_path / "fragment.yaml"
    last_good = tmp_path / "fragment.last-good.yaml"
    primary.write_text(FRAGMENT, encoding="utf-8")
    last_good.write_text("masquerade:\n  type: string\n  string:\n    content: old\n",
                         encoding="utf-8")
    text, note = choose_fragment(primary, last_good)
    assert text == FRAGMENT
    assert note == ""


def test_choose_fragment_falls_back_to_last_good(tmp_path):
    primary = tmp_path / "fragment.yaml"
    last_good = tmp_path / "fragment.last-good.yaml"
    primary.write_text("masquerade: [broken\n", encoding="utf-8")
    last_good.write_text(FRAGMENT, encoding="utf-8")
    text, note = choose_fragment(primary, last_good)
    assert text == FRAGMENT
    assert "last known-good" in note
    assert "ignored" in note


def test_choose_fragment_without_any_usable_file_returns_empty(tmp_path):
    text, note = choose_fragment(tmp_path / "missing.yaml", tmp_path / "missing2.yaml")
    assert text == ""
    assert note == ""


def test_both_broken_fragments_disable_masquerade(tmp_path):
    primary = tmp_path / "fragment.yaml"
    last_good = tmp_path / "fragment.last-good.yaml"
    primary.write_text("nope: 1\n", encoding="utf-8")
    last_good.write_text("also: broken\n", encoding="utf-8")
    text, note = choose_fragment(primary, last_good)
    assert text == ""
    assert "falling back to no masquerade section" in note


def test_read_fragment_of_a_missing_file_is_empty(tmp_path):
    assert read_fragment(tmp_path / "nope.yaml") == ""


def run_renderer(tmp_path, template: str, env: dict[str, str]) -> tuple[int, str, str]:
    template_path = tmp_path / "template.yaml"
    output = tmp_path / "out" / "server.yaml"
    template_path.write_text(template, encoding="utf-8")
    process_env = os.environ.copy()
    process_env.update(env)
    result = subprocess.run(
        [
            sys.executable,
            "bin/render_hysteria_config.py",
            str(template_path),
            str(output),
        ],
        capture_output=True,
        text=True,
        env=process_env,
        timeout=60,
    )
    return (
        result.returncode,
        output.read_text(encoding="utf-8") if output.exists() else "",
        result.stderr,
    )


def test_renderer_script_injects_the_fragment(tmp_path):
    fragment = tmp_path / "fragment.yaml"
    fragment.write_text(FRAGMENT, encoding="utf-8")
    code, text, _ = run_renderer(
        tmp_path,
        TEMPLATE,
        {**ENV, "MASQUERADE_FILE": str(fragment)},
    )
    assert code == 0
    assert "masquerade:" in text
    assert "type: file" in text
    assert "${MASQUERADE_YAML}" not in text


def test_renderer_script_without_a_fragment_keeps_old_behaviour(tmp_path):
    code, text, _ = run_renderer(
        tmp_path,
        "a: ${ACME_DOMAIN}\nb: ${ACME_EMAIL}\nc: ${TRAFFIC_STATS_SECRET}\n",
        ENV,
    )
    assert code == 0
    assert text == "a: vpn.example.com\nb: admin@example.com\nc: s3cret\n"


def test_renderer_script_falls_back_to_last_good(tmp_path):
    primary = tmp_path / "fragment.yaml"
    last_good = tmp_path / "fragment.last-good.yaml"
    primary.write_text("masquerade: [broken\n", encoding="utf-8")
    last_good.write_text(FRAGMENT, encoding="utf-8")
    code, text, stderr = run_renderer(
        tmp_path,
        TEMPLATE,
        {
            **ENV,
            "MASQUERADE_FILE": str(primary),
            "MASQUERADE_LAST_GOOD": str(last_good),
        },
    )
    assert code == 0
    assert "masquerade:" in text
    assert "last known-good" in stderr


def test_renderer_script_fails_loudly_without_environment(tmp_path):
    code, _text, stderr = run_renderer(tmp_path, TEMPLATE, {"ACME_DOMAIN": "x.example"})
    assert code == 1
    assert "missing environment variables" in stderr


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX file modes are not enforced on NTFS")
def test_renderer_output_is_not_world_readable(tmp_path):
    fragment = tmp_path / "fragment.yaml"
    fragment.write_text(FRAGMENT, encoding="utf-8")
    code, _text, _ = run_renderer(
        tmp_path, TEMPLATE, {**ENV, "MASQUERADE_FILE": str(fragment)}
    )
    assert code == 0
    assert (tmp_path / "out" / "server.yaml").stat().st_mode & 0o777 == 0o600
