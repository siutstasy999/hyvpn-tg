"""Transactional deployment: backup, validate, atomic swap, verify, rollback."""

from __future__ import annotations

import sys
import time
from pathlib import Path

import pytest

from core.hysteria_config import render
from core.masquerade.config import MasqConfig
from core.masquerade.deploy import Deployer, Http3Result
from core.masquerade.render import effective_mode_of
from tests.masq_fakes import capabilities, failed, make_paths, ok, seed_template

DOMAIN = "vpn.example.com"
ENV = {
    "ACME_DOMAIN": DOMAIN,
    "ACME_EMAIL": "admin@example.com",
    "TRAFFIC_STATS_SECRET": "secret",
}


class ServiceRunner:
    """Fake systemctl that also emulates the unit's ExecStartPre renderer."""

    def __init__(
        self,
        paths,
        *,
        fail_restarts: int = 0,
        fail_restart: bool | None = None,
        inject: str | None = None,
        check_ok: bool = True,
        crash_after_first_restart: bool = False,
    ):
        self.paths = paths
        # ``fail_restarts`` is a count so a test can make the *apply* restart
        # fail while the rollback restart succeeds.
        self.fail_restarts = fail_restarts if fail_restart is None else (1 if fail_restart else 0)
        self.inject = inject
        self.check_ok = check_ok
        self.crash_after_first_restart = crash_after_first_restart
        self.calls: list[list[str]] = []
        self.active = True
        self.restarts = 0

    def __call__(self, args, **kwargs):
        self.calls.append(list(args))
        joined = " ".join(args)
        if args and args[0].endswith("hysteria") and "check" in args:
            return ok("config ok") if self.check_ok else failed("unknown field: masquerade.foo")
        if args and args[0] == "systemctl":
            action = args[1] if len(args) > 1 else ""
            if action == "is-active":
                return ok("active" if self.active else "inactive")
            if action == "restart":
                self.restarts += 1
                if self.fail_restarts > 0:
                    self.fail_restarts -= 1
                    return failed("unit failed to start")
                self.render_runtime()
                if self.crash_after_first_restart and self.restarts == 1:
                    self.active = False
                else:
                    self.active = True
                return ok()
        assert " curl " not in f" {joined} "
        return ok()

    def render_runtime(self):
        if self.inject is not None:
            text = self.inject
        else:
            template = self.paths.template.read_text(encoding="utf-8")
            fragment = (
                self.paths.fragment.read_text(encoding="utf-8")
                if self.paths.fragment.exists()
                else ""
            )
            text = render(template, ENV, fragment)
        self.paths.runtime_config.parent.mkdir(parents=True, exist_ok=True)
        self.paths.runtime_config.write_text(text, encoding="utf-8")

    def count(self, *needle: str) -> int:
        return sum(1 for call in self.calls if all(item in " ".join(call) for item in needle))


def http3(ok_value: bool, detail: str = "HTTP 200 over HTTP/3"):
    def checker(domain, port=443, runner=None):
        return Http3Result(
            available=True,
            ok=ok_value,
            status=200 if ok_value else None,
            detail=detail,
        )

    return checker


def make_deployer(tmp_path, *, runner=None, http3_checker=None, config=None, caps=None):
    paths = make_paths(tmp_path)
    seed_template(paths)
    runner = runner or ServiceRunner(paths)
    return (
        Deployer(
            paths,
            domain=DOMAIN,
            config=config or MasqConfig(mode="auto"),
            capabilities=caps or capabilities(),
            runner=runner,
            http3_checker=http3_checker or http3(True),
            sleep=lambda _seconds: None,
            service_timeout=0.1,
        ),
        paths,
        runner,
    )


# --------------------------------------------------------------------------- #
# apply
# --------------------------------------------------------------------------- #

def test_file_mode_writes_the_fragment_and_restarts_once(tmp_path):
    deployer, paths, runner = make_deployer(tmp_path)
    result = deployer.apply("file", reason="test")
    assert result.applied
    assert result.verified
    assert not result.rolled_back
    assert effective_mode_of(paths.fragment.read_text(encoding="utf-8")) == "file"
    assert runner.count("systemctl", "restart", "hysteria-server.service") == 1
    expected = f"dir: {paths.site_dir}"
    assert expected in paths.fragment.read_text(encoding="utf-8")


def test_proxy_mode_records_the_upstream_and_keeps_tls_untouched(tmp_path):
    deployer, paths, _runner = make_deployer(tmp_path)
    result = deployer.apply("proxy", upstream_url="https://origin.example/")
    assert result.applied
    fragment = paths.fragment.read_text(encoding="utf-8")
    assert "url: https://origin.example/" in fragment
    assert "insecure: false" in fragment
    # The TLS identity is still the template's: the domain did not move.
    runtime = paths.runtime_config.read_text(encoding="utf-8")
    assert f"- {DOMAIN}" in runtime


def test_unchanged_fragment_does_not_touch_the_service(tmp_path):
    deployer, paths, runner = make_deployer(tmp_path)
    deployer.apply("file", reason="first")
    restarts_before = runner.count("systemctl", "restart")
    result = deployer.apply("file", reason="again")
    assert not result.changed
    assert not result.applied
    assert runner.count("systemctl", "restart") == restarts_before
    assert "already in place" in " ".join(result.notes)


def test_dry_run_validates_without_writing(tmp_path):
    deployer, paths, runner = make_deployer(tmp_path)
    result = deployer.apply("file", dry_run=True)
    assert result.dry_run
    assert result.changed
    assert not result.applied
    assert not paths.fragment.exists()
    assert runner.count("systemctl", "restart") == 0


def test_invalid_configuration_is_rejected_before_writing(tmp_path):
    deployer, paths, runner = make_deployer(tmp_path)
    # A template whose ACME domain does not match the configured domain.
    paths.template.write_text(
        "listen: :443\nacme:\n  domains:\n    - other.example\n  email: ${ACME_EMAIL}\n"
        "  dir: /var/lib/acme\ntrafficStats:\n  secret: ${TRAFFIC_STATS_SECRET}\n"
        "${MASQUERADE_YAML}\n",
        encoding="utf-8",
    )
    result = deployer.apply("file")
    assert not result.applied
    assert not result.changed or result.changed
    assert any("does not contain" in error for error in result.errors)
    assert not paths.fragment.exists()
    assert runner.count("systemctl", "restart") == 0


def test_previous_configuration_is_backed_up(tmp_path):
    deployer, paths, _runner = make_deployer(tmp_path)
    deployer.apply("file", reason="first")
    previous = paths.fragment.read_text(encoding="utf-8")
    result = deployer.apply("proxy", upstream_url="https://origin.example/")
    assert result.backup is not None
    backup = Path(result.backup)
    assert backup.read_text(encoding="utf-8") == previous
    meta = backup.with_suffix(".json")
    assert meta.is_file()
    assert "file" in meta.read_text(encoding="utf-8")


def test_last_known_good_copy_is_updated(tmp_path):
    deployer, paths, _runner = make_deployer(tmp_path)
    deployer.apply("file")
    last_good = paths.fragment.with_name(paths.fragment.name + ".last-good")
    assert last_good.is_file()
    assert effective_mode_of(last_good.read_text(encoding="utf-8")) == "file"


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX file modes are not enforced on NTFS")
def test_fragment_permissions_are_group_readable_only(tmp_path):
    deployer, paths, _runner = make_deployer(tmp_path)
    deployer.apply("file")
    assert paths.fragment.stat().st_mode & 0o777 == 0o640


# --------------------------------------------------------------------------- #
# verification and rollback
# --------------------------------------------------------------------------- #

def test_runtime_mismatch_rolls_back(tmp_path):
    paths = make_paths(tmp_path)
    seed_template(paths)
    stale = render(paths.template.read_text(encoding="utf-8"), ENV, "")
    runner = ServiceRunner(paths, inject=stale)
    deployer = Deployer(
        paths,
        domain=DOMAIN,
        capabilities=capabilities(),
        runner=runner,
        http3_checker=http3(True),
        sleep=lambda _s: None,
        service_timeout=0.1,
    )
    # Put a known-good fragment in place first so the rollback has something.
    paths.fragment.parent.mkdir(parents=True, exist_ok=True)
    paths.fragment.write_text(
        "masquerade:\n  type: string\n  string:\n    content: previous\n",
        encoding="utf-8",
    )
    result = deployer.apply("proxy", upstream_url="https://origin.example/")
    assert result.rolled_back
    assert result.errors
    assert "strin" in paths.fragment.read_text(encoding="utf-8")
    assert runner.count("systemctl", "restart") == 2


def test_restart_failure_rolls_back(tmp_path):
    paths = make_paths(tmp_path)
    seed_template(paths)
    runner = ServiceRunner(paths, fail_restarts=1)
    deployer = Deployer(
        paths,
        domain=DOMAIN,
        capabilities=capabilities(),
        runner=runner,
        http3_checker=http3(True),
        sleep=lambda _s: None,
        service_timeout=0.1,
    )
    paths.fragment.parent.mkdir(parents=True, exist_ok=True)
    previous = "masquerade:\n  type: string\n  string:\n    content: previous\n"
    paths.fragment.write_text(previous, encoding="utf-8")
    result = deployer.apply("file")
    assert result.rolled_back
    assert any("unit failed" in error for error in result.errors)
    assert paths.fragment.read_text(encoding="utf-8") == previous
    assert runner.restarts == 2


def test_inactive_service_is_a_verification_failure(tmp_path):
    paths = make_paths(tmp_path)
    seed_template(paths)
    runner = ServiceRunner(paths, crash_after_first_restart=True)
    deployer = Deployer(
        paths,
        domain=DOMAIN,
        capabilities=capabilities(),
        runner=runner,
        http3_checker=http3(True),
        sleep=lambda _s: None,
        service_timeout=0.05,
    )
    result = deployer.apply("file")
    assert result.rolled_back
    assert any(
        "not active" in error or "did not become active" in error
        for error in result.errors
    )


def test_http3_failure_rolls_back_only_when_the_check_worked_before(tmp_path):
    deployer, paths, _runner = make_deployer(tmp_path)
    paths.fragment.parent.mkdir(parents=True, exist_ok=True)
    paths.fragment.write_text(
        "masquerade:\n  type: string\n  string:\n    content: previous\n",
        encoding="utf-8",
    )

    # The baseline passes, the configuration after the change does not.
    results = iter(
        [
            Http3Result(available=True, ok=True, status=200, detail="HTTP 200 over HTTP/3"),
            Http3Result(available=True, ok=False, detail="timeout"),
        ]
    )
    deployer._http3 = lambda *args, **kwargs: next(results)  # noqa: SLF001
    deployer._http3_takes_runner = True  # noqa: SLF001

    result = deployer.apply("proxy", upstream_url="https://origin.example/")
    assert result.rolled_back
    assert any("HTTP/3" in error for error in result.errors)


def test_http3_is_not_a_gate_when_the_baseline_failed(tmp_path):
    deployer, paths, _runner = make_deployer(
        tmp_path, http3_checker=http3(False, detail="connection refused")
    )
    paths.fragment.parent.mkdir(parents=True, exist_ok=True)
    paths.fragment.write_text("masquerade:\n  type: none\n", encoding="utf-8")
    result = deployer.apply("proxy", upstream_url="https://origin.example/")
    assert result.applied
    assert result.verified
    assert not result.rolled_back


def test_binary_config_check_is_used_when_available(tmp_path):
    caps = capabilities(config_check=["check", "-c"])
    paths = make_paths(tmp_path)
    seed_template(paths)
    runner = ServiceRunner(paths, check_ok=False)
    deployer = Deployer(
        paths,
        domain=DOMAIN,
        capabilities=caps,
        runner=runner,
        http3_checker=http3(True),
        sleep=lambda _s: None,
        service_timeout=0.1,
    )
    result = deployer.apply("file")
    assert not result.applied
    assert any("config check failed" in error for error in result.errors)
    assert runner.count("hysteria", "check") == 1


def test_binary_config_check_absence_is_reported_as_a_note(tmp_path):
    deployer, paths, _runner = make_deployer(tmp_path)
    from core.masquerade import site as site_builder

    site_builder.materialize(paths.site_dir, domain=DOMAIN)
    fragment = deployer.build_fragment("file")
    ok_, errors, _warnings, notes = deployer.validate("file", fragment)
    assert ok_, errors
    assert any("no config check command" in note for note in notes)


# --------------------------------------------------------------------------- #
# housekeeping
# --------------------------------------------------------------------------- #

def test_backup_rotation_keeps_the_newest_entries(tmp_path):
    deployer, paths, _runner = make_deployer(tmp_path)
    paths.fragment.parent.mkdir(parents=True, exist_ok=True)
    paths.fragment.write_text(
        "masquerade:\n  type: string\n  string:\n    content: previous\n",
        encoding="utf-8",
    )
    paths.backups.mkdir(parents=True, exist_ok=True)
    for index in range(25):
        (paths.backups / f"fragment-20200101-000000-{index:06d}.yaml").write_text(
            "old", encoding="utf-8"
        )
        time.sleep(0.001)
    deployer.apply("file")
    kept = list(paths.backups.glob("fragment-*.yaml"))
    assert 1 <= len(kept) <= 20


def test_atomic_write_leaves_no_temporary_file(tmp_path):
    from core.hysteria_config import atomic_write

    target = tmp_path / "out" / "file.yaml"
    atomic_write(target, "hello\n", mode=0o640)
    assert target.read_text(encoding="utf-8") == "hello\n"
    assert not list(target.parent.glob("*.tmp"))


def test_staging_directory_is_cleaned_up(tmp_path):
    deployer, paths, _runner = make_deployer(tmp_path)
    caps = capabilities(config_check=["check", "-c"])
    deployer.capabilities = caps
    deployer.apply("file")
    staging = paths.state_dir / "staging"
    assert not staging.exists() or not list(staging.glob("*.yaml"))
