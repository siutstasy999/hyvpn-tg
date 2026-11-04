"""CLI behaviour: read-only commands never write, write commands ask first."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

from core.masquerade import cli
from tests.masq_fakes import make_paths, seed_template


class Output:
    def __init__(self) -> None:
        self.lines: list[str] = []
        self.errors: list[str] = []

    def out(self, text: str) -> None:
        self.lines.append(str(text))

    def err(self, text: str) -> None:
        self.errors.append(str(text))

    @property
    def text(self) -> str:
        return "\n".join(self.lines)

    @property
    def error_text(self) -> str:
        return "\n".join(self.errors)


def make_ctx(
    tmp_path,
    *,
    json_output: bool = False,
    assume_yes: bool = True,
    interactive: bool = False,
):
    paths = make_paths(tmp_path)
    seed_template(paths)
    output = Output()
    context = cli.Context(
        paths=paths,
        domain="vpn.example.com",
        server_port=443,
        acme_dir=str(tmp_path / "acme"),
        cert_status_path=str(tmp_path / "cert.json"),
        json_output=json_output,
        assume_yes=assume_yes,
        interactive=interactive,
        out=output.out,
        err=output.err,
    )
    return context, paths, output


# --------------------------------------------------------------------------- #
# status / check
# --------------------------------------------------------------------------- #

def test_status_reports_the_configured_and_effective_mode(tmp_path):
    context, _paths, output = make_ctx(tmp_path)
    assert cli.cmd_status(context) == cli.EXIT_OK
    text = output.text
    assert "configured mode" in text
    assert "effective mode" in text
    assert "auto" in text
    assert "TLS" in text
    assert "Fallback site" in text


def test_status_json_is_machine_readable(tmp_path):
    context, _paths, output = make_ctx(tmp_path, json_output=True)
    assert cli.cmd_status(context) == cli.EXIT_OK
    payload = json.loads(output.text)
    assert payload["configured_mode"] == "auto"
    assert payload["effective_mode"] == "none"
    assert "certificate_sans" in payload
    assert payload["capabilities"]["present"] in (True, False)


def test_check_without_candidates_is_ok_but_warns_about_the_site(tmp_path):
    context, paths, output = make_ctx(tmp_path)
    code = cli.cmd_check(context)
    assert code == cli.EXIT_OK
    assert "локальный" not in output.text  # English CLI
    assert "fallback site" in output.text
    assert not paths.fragment.exists()


def test_check_fails_on_a_broken_configuration(tmp_path):
    context, paths, output = make_ctx(tmp_path)
    paths.config.parent.mkdir(parents=True, exist_ok=True)
    paths.config.write_text("{broken", encoding="utf-8")
    code = cli.cmd_check(context)
    assert code == cli.EXIT_FAIL
    assert "masquerade.json" in output.text


# --------------------------------------------------------------------------- #
# optimize
# --------------------------------------------------------------------------- #

def test_optimize_dry_run_prints_a_plan_and_writes_no_config(tmp_path):
    context, paths, output = make_ctx(tmp_path)
    args = argparse.Namespace(dry_run=True, apply=False, yes=True, json=False)
    code = cli.cmd_optimize(context, args)
    assert code == cli.EXIT_OK
    assert "Proposed configuration" in output.text
    assert not paths.fragment.exists()
    assert not paths.config.exists()


def test_optimize_dry_run_json(tmp_path):
    context, _paths, output = make_ctx(tmp_path, json_output=True)
    args = argparse.Namespace(dry_run=True, apply=False, yes=True, json=True)
    assert cli.cmd_optimize(context, args) == cli.EXIT_OK
    payload = json.loads(output.text)
    assert payload["mode"] == "file"
    assert payload["changed"] is True


def test_optimize_apply_requires_root(tmp_path, monkeypatch):
    context, paths, output = make_ctx(tmp_path)
    monkeypatch.setattr(os, "geteuid", lambda: 1000, raising=False)
    args = argparse.Namespace(dry_run=False, apply=True, yes=True, json=False)
    code = cli.cmd_optimize(context, args)
    assert code == cli.EXIT_FAIL
    assert "root" in output.error_text
    assert not paths.fragment.exists()


def test_optimize_apply_refuses_without_confirmation(tmp_path, monkeypatch):
    monkeypatch.setattr(os, "geteuid", lambda: 0, raising=False)
    context, paths, output = make_ctx(tmp_path, assume_yes=False, interactive=False)
    args = argparse.Namespace(dry_run=False, apply=True, yes=False, json=False)
    code = cli.cmd_optimize(context, args)
    assert code == cli.EXIT_FAIL
    assert "confirmation" in output.error_text
    assert not paths.fragment.exists()


# --------------------------------------------------------------------------- #
# candidates
# --------------------------------------------------------------------------- #

def test_candidates_list_without_entries_explains_what_to_do(tmp_path):
    context, _paths, output = make_ctx(tmp_path)
    assert cli.cmd_candidates_list(context) == cli.EXIT_OK
    assert "No candidates configured" in output.text
    assert "candidates add" in output.text


def test_candidates_add_rejects_non_https_urls(tmp_path):
    context, _paths, output = make_ctx(tmp_path)
    args = argparse.Namespace(
        url="http://origin.example/", id=None, priority=0, description="", replace=False
    )
    assert cli.cmd_candidates_add(context, args) == cli.EXIT_USAGE
    assert "https" in output.error_text


def test_candidates_add_writes_the_registry(tmp_path, monkeypatch):
    monkeypatch.setattr(os, "geteuid", lambda: 0, raising=False)
    context, paths, output = make_ctx(tmp_path)
    args = argparse.Namespace(
        url="https://origin.example/",
        id="origin",
        priority=3,
        description="own site",
        replace=False,
    )
    assert cli.cmd_candidates_add(context, args) == cli.EXIT_OK
    payload = json.loads(paths.config.read_text(encoding="utf-8"))
    assert payload["candidates"] == [
        {
            "id": "origin",
            "url": "https://origin.example/",
            "enabled": True,
            "priority": 3,
            "description": "own site",
        }
    ]
    assert "origin" in output.text


def test_candidates_add_derives_a_safe_id(tmp_path, monkeypatch):
    monkeypatch.setattr(os, "geteuid", lambda: 0, raising=False)
    context, paths, _output = make_ctx(tmp_path)
    args = argparse.Namespace(
        url="https://vpn.example.com/", id=None, priority=0, description="", replace=False
    )
    assert cli.cmd_candidates_add(context, args) == cli.EXIT_OK
    assert json.loads(paths.config.read_text(encoding="utf-8"))["candidates"][0]["id"] == (
        "vpn-example-com"
    )


def test_candidates_can_be_disabled_and_removed(tmp_path, monkeypatch):
    monkeypatch.setattr(os, "geteuid", lambda: 0, raising=False)
    context, paths, _output = make_ctx(tmp_path)
    cli.cmd_candidates_add(
        context,
        argparse.Namespace(
            url="https://origin.example/", id="origin", priority=0, description="", replace=False
        ),
    )
    assert cli.cmd_candidates_enable(
        context, argparse.Namespace(id="origin"), False
    ) == cli.EXIT_OK
    assert json.loads(paths.config.read_text(encoding="utf-8"))["candidates"][0]["enabled"] is False
    assert cli.cmd_candidates_remove(context, argparse.Namespace(id="origin")) == cli.EXIT_OK
    assert json.loads(paths.config.read_text(encoding="utf-8"))["candidates"] == []


# --------------------------------------------------------------------------- #
# init and set-mode
# --------------------------------------------------------------------------- #

def test_init_creates_config_site_and_fragment(tmp_path, monkeypatch):
    monkeypatch.setattr(os, "geteuid", lambda: 0, raising=False)
    context, paths, _output = make_ctx(tmp_path)
    args = argparse.Namespace(no_restart=True, json=False)
    code = cli.cmd_init(context, args)
    assert code in (cli.EXIT_OK, cli.EXIT_FAIL)
    assert (paths.site_dir / "index.html").is_file()
    assert paths.config.is_file()
    assert paths.fragment.is_file()
    assert "type: file" in paths.fragment.read_text(encoding="utf-8")


def test_set_mode_dry_run_does_not_write(tmp_path, monkeypatch):
    monkeypatch.setattr(os, "geteuid", lambda: 0, raising=False)
    context, paths, output = make_ctx(tmp_path)
    args = argparse.Namespace(mode="file", dry_run=True, yes=True, json=False)
    assert cli.cmd_set_mode(context, args) == cli.EXIT_OK
    assert not paths.config.exists()
    assert not paths.fragment.exists()
    assert "dry-run" in output.text


# --------------------------------------------------------------------------- #
# the bot → root request worker
# --------------------------------------------------------------------------- #

def install_fake_engine(monkeypatch, paths, *, cfg, probes):
    from core.masquerade.engine import MasqueradeEngine
    from core.masquerade.models import Thresholds
    from tests.masq_fakes import (
        FakeDeployer,
        FakeProber,
        candidate,
        capabilities,
        config,
        probe_result,
    )

    cfg = cfg or config(candidate("own"), thresholds=Thresholds(min_samples=1))
    deployer = FakeDeployer(paths=paths, domain="vpn.example.com")
    engine = MasqueradeEngine(
        paths,
        domain="vpn.example.com",
        config=cfg,
        prober=FakeProber(probes or {"own": [probe_result("own")]}),
        deployer=deployer,
        capabilities=capabilities(),
        sleep=lambda _s: None,
    )
    monkeypatch.setattr(cli.Context, "engine", lambda self, config=None: engine)
    return engine, deployer


def test_apply_requests_runs_optimize_and_records_a_result(tmp_path, monkeypatch):
    monkeypatch.setattr(os, "geteuid", lambda: 0, raising=False)
    context, paths, output = make_ctx(tmp_path)
    from core.masquerade import requests as masq_requests

    install_fake_engine(monkeypatch, paths, cfg=None, probes=None)
    request_id = masq_requests.submit(paths, "optimize", requested_by=1)
    assert cli.cmd_apply_requests(context) == cli.EXIT_OK
    assert not (paths.request_dir / f"{request_id}.json").exists()
    results = masq_requests.read_results(paths)
    assert results and results[0]["result"]["ok"] is True
    assert results[0]["result"]["action"] == "optimize"
    assert "processed 1 request" in output.text


def test_apply_requests_handles_set_mode(tmp_path, monkeypatch):
    monkeypatch.setattr(os, "geteuid", lambda: 0, raising=False)
    context, paths, _output = make_ctx(tmp_path)
    from core.masquerade import requests as masq_requests

    install_fake_engine(monkeypatch, paths, cfg=None, probes=None)
    masq_requests.submit(paths, "set-mode", payload={"mode": "file"})
    cli.cmd_apply_requests(context)
    results = masq_requests.read_results(paths)
    assert results[0]["result"]["ok"] is True
    assert results[0]["result"]["mode"] == "file"


def test_apply_requests_reports_a_broken_registry(tmp_path, monkeypatch):
    monkeypatch.setattr(os, "geteuid", lambda: 0, raising=False)
    context, paths, _output = make_ctx(tmp_path)
    from core.masquerade import requests as masq_requests

    masq_requests.submit(paths, "optimize")
    paths.config.parent.mkdir(parents=True, exist_ok=True)
    paths.config.write_text("{broken", encoding="utf-8")
    code = cli.cmd_apply_requests(context)
    assert code == cli.EXIT_FAIL
    results = masq_requests.read_results(paths)
    assert results[0]["result"]["ok"] is False
    error = results[0]["result"]["error"]
    assert "masquerade.json" in error or "invalid" in error


def test_apply_requests_with_nothing_queued_is_a_no_op(tmp_path, monkeypatch):
    monkeypatch.setattr(os, "geteuid", lambda: 0, raising=False)
    context, _paths, output = make_ctx(tmp_path)
    assert cli.cmd_apply_requests(context) == cli.EXIT_OK
    assert "no pending requests" in output.text


def test_apply_requests_requires_root(tmp_path, monkeypatch):
    monkeypatch.setattr(os, "geteuid", lambda: 1000, raising=False)
    context, _paths, output = make_ctx(tmp_path)
    assert cli.cmd_apply_requests(context) == cli.EXIT_FAIL
    assert "root" in output.error_text


# --------------------------------------------------------------------------- #
# the real argparse wiring
# --------------------------------------------------------------------------- #

def run_cli(tmp_path, *args: str) -> subprocess.CompletedProcess:
    paths = make_paths(tmp_path)
    environment = os.environ.copy()
    environment.update(
        {
            "SERVER_DOMAIN": "vpn.example.com",
            "SERVER_PORT": "443",
            "HYSTERIA_STATS_SECRET": "test-secret",
            "MASQ_CONFIG_PATH": str(paths.config),
            "MASQ_STATE_DIR": str(paths.state_dir),
            "MASQ_SITE_DIR": str(paths.site_dir),
            "MASQ_FRAGMENT_PATH": str(paths.fragment),
            "MASQ_RUNTIME_CONFIG": str(paths.runtime_config),
            "MASQ_TEMPLATE": str(paths.template),
            "MASQ_BACKUP_DIR": str(paths.backups),
            "HYSTERIA_BINARY": str(paths.hysteria_binary),
            "ACME_DIR": str(tmp_path / "acme"),
            "CERT_STATUS_PATH": str(tmp_path / "cert.json"),
        }
    )
    return subprocess.run(
        [sys.executable, "hy-cli.py", "masquerade", *args],
        capture_output=True,
        text=True,
        env=environment,
        timeout=120,
    )


def test_the_masquerade_subcommand_is_wired_into_hy_cli(tmp_path):
    result = run_cli(tmp_path, "status", "--json")
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["configured_mode"] == "auto"
    assert Path(payload["config_path"]) == make_paths(tmp_path).config


def test_unknown_masquerade_command_fails_with_a_usage_error(tmp_path):
    result = run_cli(tmp_path, "definitely-not-a-command")
    assert result.returncode != 0
    assert "invalid choice" in result.stderr


def test_help_lists_the_masquerade_commands(tmp_path):
    result = subprocess.run(
        [sys.executable, "hy-cli.py", "masquerade", "--help"],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0
    for command in ("status", "check", "doctor", "candidates", "optimize", "set-mode", "upgrade"):
        assert command in result.stdout


def test_set_mode_rejects_an_unknown_mode(tmp_path):
    result = run_cli(tmp_path, "set-mode", "carrier-pigeon")
    assert result.returncode != 0
    assert "invalid choice" in result.stderr
