"""Read-only diagnostics: environment report, redaction, foreign upstream."""

from __future__ import annotations

from core.masquerade import cli, diagnostics
from core.masquerade.config import default_config, write_config
from tests.masq_fakes import make_paths, ok, seed_template

DOMAIN = "vpn.example.com"


class DiagRunner:
    def __init__(self, responses: dict[str, object] | None = None):
        self.responses = responses or {}
        self.calls: list[list[str]] = []

    def __call__(self, args, **kwargs):
        self.calls.append(list(args))
        joined = " ".join(args)
        for pattern, value in self.responses.items():
            if pattern in joined:
                return value() if callable(value) else value
        return ok("")

    def names(self) -> list[str]:
        return [" ".join(call) for call in self.calls]


def base_runner(*, version: str = "Version: v2.6.0", help_text: str = "  server\n  version\n"):
    return DiagRunner(
        {
            "hysteria version": ok(version),
            "hysteria --help": ok(help_text),
            "systemctl show": ok(
                "FragmentPath=/etc/systemd/system/hysteria-server.service\n"
                "User=hysteria\n"
                "Group=hyvpn\n"
                "ActiveState=active\n"
            ),
            "ss -H -lntu": ok(
                "udp   UNCONN 0 0 0.0.0.0:443 0.0.0.0:*\n"
                "tcp   LISTEN 0 4096 0.0.0.0:22 0.0.0.0:*\n"
            ),
        }
    )


def write_fragment(paths, body: str) -> None:
    paths.fragment.parent.mkdir(parents=True, exist_ok=True)
    paths.fragment.write_text(body, encoding="utf-8")


def test_report_collects_the_environment(tmp_path, monkeypatch):
    paths = make_paths(tmp_path)
    seed_template(paths)
    paths.hysteria_binary.parent.mkdir(parents=True, exist_ok=True)
    paths.hysteria_binary.write_text("#!/bin/sh\n", encoding="utf-8")
    write_config(paths, default_config())
    monkeypatch.setattr(diagnostics.shutil, "which", lambda name: f"/usr/bin/{name}")
    runner = base_runner()
    report = diagnostics.collect(
        paths, domain=DOMAIN, server_port=443, acme_dir=str(tmp_path / "acme"), runner=runner
    )
    sections = report.sections
    assert sections["system"]["architecture"]
    assert sections["hysteria"]["version"] == "2.6.0"
    assert sections["hysteria"]["supports_masquerade"] is True
    assert sections["service"]["ActiveState"] == "active"
    assert any(item["local"].endswith(":443") for item in sections["ports"]["udp"])
    assert sections["masquerade"]["mode"] == "none"
    assert report.capabilities is not None
    assert "hysteria version" in " ".join(runner.names())


def test_old_hysteria_is_an_error(tmp_path):
    paths = make_paths(tmp_path)
    seed_template(paths)
    paths.hysteria_binary.parent.mkdir(parents=True, exist_ok=True)
    paths.hysteria_binary.write_text("#!/bin/sh\n", encoding="utf-8")
    runner = base_runner(version="Version: v1.3.5")
    report = diagnostics.collect(
        paths, domain=DOMAIN, acme_dir=str(tmp_path / "acme"), runner=runner
    )
    assert not report.ok
    assert any("does not support masquerade" in error for error in report.errors)


def test_missing_binary_is_an_error(tmp_path, monkeypatch):
    paths = make_paths(tmp_path)
    seed_template(paths)
    monkeypatch.setattr("shutil.which", lambda _name: None)
    report = diagnostics.collect(
        paths, domain=DOMAIN, acme_dir=str(tmp_path / "acme"), runner=base_runner()
    )
    assert not report.ok
    assert any("not found" in error for error in report.errors)


def test_a_foreign_upstream_is_flagged(tmp_path):
    paths = make_paths(tmp_path)
    seed_template(paths)
    write_fragment(
        paths,
        "masquerade:\n  type: proxy\n  proxy:\n"
        "    url: https://www.google.com/\n    rewriteHost: true\n"
        "    insecure: false\n    xForwarded: false\n",
    )
    report = diagnostics.collect(
        paths, domain=DOMAIN, acme_dir=str(tmp_path / "acme"), runner=base_runner()
    )
    assert report.sections["masquerade"]["upstream"] == "https://www.google.com/"
    assert any("not in the candidate registry" in warning for warning in report.warnings)


def test_a_registered_upstream_is_not_flagged(tmp_path):
    paths = make_paths(tmp_path)
    seed_template(paths)
    write_fragment(
        paths,
        "masquerade:\n  type: proxy\n  proxy:\n"
        "    url: https://vpn.example.com/\n    rewriteHost: true\n"
        "    insecure: false\n    xForwarded: false\n",
    )
    config = default_config()
    from core.masquerade.models import Candidate

    config.candidates.append(Candidate(id="own", url="https://vpn.example.com/"))
    write_config(paths, config)
    report = diagnostics.collect(
        paths, domain=DOMAIN, acme_dir=str(tmp_path / "acme"), runner=base_runner()
    )
    assert not any("candidate registry" in warning for warning in report.warnings)


def test_insecure_and_private_upstreams_are_errors(tmp_path):
    paths = make_paths(tmp_path)
    seed_template(paths)
    write_fragment(
        paths,
        "masquerade:\n  type: proxy\n  proxy:\n"
        "    url: https://127.0.0.1/\n    insecure: true\n",
    )
    report = diagnostics.collect(
        paths, domain=DOMAIN, acme_dir=str(tmp_path / "acme"), runner=base_runner()
    )
    assert any("non-public" in error for error in report.errors)
    assert any("certificate verification" in error for error in report.errors)


def test_certificate_sans_are_reported(tmp_path, monkeypatch):
    paths = make_paths(tmp_path)
    seed_template(paths)
    certificate = tmp_path / "acme" / "vpn.example.com.crt"
    certificate.parent.mkdir(parents=True, exist_ok=True)
    certificate.write_text("-----BEGIN CERTIFICATE-----", encoding="utf-8")
    monkeypatch.setattr(diagnostics, "find_cert_file", lambda domain, acme: certificate)
    monkeypatch.setattr(
        diagnostics, "openssl_sans", lambda path, runner=None: [DOMAIN, "www.example.com"]
    )
    report = diagnostics.collect(
        paths, domain=DOMAIN, acme_dir=str(certificate.parent), runner=base_runner()
    )
    section = report.sections["certificate"]
    assert section["found"] is True
    assert section["covers_domain"] is True
    assert section["sans"] == [DOMAIN, "www.example.com"]


def test_a_certificate_for_another_domain_is_an_error(tmp_path, monkeypatch):
    paths = make_paths(tmp_path)
    seed_template(paths)
    certificate = tmp_path / "other.crt"
    certificate.write_text("x", encoding="utf-8")
    monkeypatch.setattr(diagnostics, "find_cert_file", lambda domain, acme: certificate)
    monkeypatch.setattr(
        diagnostics, "openssl_sans", lambda path, runner=None: ["other.example"]
    )
    report = diagnostics.collect(
        paths, domain=DOMAIN, acme_dir=str(tmp_path), runner=base_runner()
    )
    assert any("does not cover" in error for error in report.errors)


def test_secrets_are_redacted_from_environment_listing(tmp_path):
    env_file = tmp_path / ".env.core"
    env_file.write_text(
        "SERVER_DOMAIN=vpn.example.com\nHYSTERIA_STATS_SECRET=super-secret\nBOT_TOKEN=123:abc\n",
        encoding="utf-8",
    )
    keys = diagnostics._env_keys(env_file)
    assert "SERVER_DOMAIN" in keys
    assert "HYSTERIA_STATS_SECRET=<redacted>" in keys
    assert "BOT_TOKEN=<redacted>" in keys
    assert not any("super-secret" in key for key in keys)


def test_report_never_contains_secret_values(tmp_path, monkeypatch):
    paths = make_paths(tmp_path)
    seed_template(paths)
    env_dir = tmp_path / "etc"
    env_dir.mkdir(parents=True, exist_ok=True)
    (env_dir / ".env.hysteria").write_text(
        "TRAFFIC_STATS_SECRET=do-not-leak\n", encoding="utf-8"
    )
    report = diagnostics.collect(
        paths, domain=DOMAIN, acme_dir=str(tmp_path / "acme"), runner=base_runner()
    )
    assert "do-not-leak" not in str(report.to_json())


def test_doctor_command_prints_a_readable_report(tmp_path):
    paths = make_paths(tmp_path)
    seed_template(paths)
    output: list[str] = []
    context = cli.Context(
        paths=paths,
        domain=DOMAIN,
        acme_dir=str(tmp_path / "acme"),
        out=output.append,
        err=output.append,
        json_output=False,
        runner=base_runner(),
    )
    code = cli.cmd_doctor(context)
    text = "\n".join(output)
    assert code in (cli.EXIT_OK, cli.EXIT_FAIL)
    assert "Hysteria2" in text
    assert "Masquerade" in text
    assert "Listening on port" in text


def test_doctor_json_output(tmp_path):
    paths = make_paths(tmp_path)
    seed_template(paths)
    output: list[str] = []
    context = cli.Context(
        paths=paths,
        domain=DOMAIN,
        acme_dir=str(tmp_path / "acme"),
        out=output.append,
        err=output.append,
        json_output=True,
        runner=base_runner(),
    )
    cli.cmd_doctor(context)
    import json

    payload = json.loads(output[-1])
    assert payload["domain"] == DOMAIN
    assert "sections" in payload
