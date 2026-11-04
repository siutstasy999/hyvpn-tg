"""The bot → root request queue and the local fallback site."""

from __future__ import annotations

import json
import sys
import time

import pytest

from core.masquerade import requests as masq_requests
from core.masquerade import site as site_builder
from tests.masq_fakes import make_paths

# --------------------------------------------------------------------------- #
# request queue
# --------------------------------------------------------------------------- #

def test_a_request_is_written_atomically(tmp_path):
    paths = make_paths(tmp_path)
    request_id = masq_requests.submit(
        paths, "optimize", payload={}, requested_by=42
    )
    target = paths.request_dir / f"{request_id}.json"
    assert target.is_file()
    payload = json.loads(target.read_text(encoding="utf-8"))
    assert payload["kind"] == "optimize"
    assert payload["requested_by"] == 42
    assert not list(paths.request_dir.glob("*.tmp"))


def test_unknown_request_kinds_are_refused(tmp_path):
    with pytest.raises(ValueError):
        masq_requests.submit(make_paths(tmp_path), "restart-everything")


def test_pending_requests_are_listed_and_discarded(tmp_path):
    paths = make_paths(tmp_path)
    first = masq_requests.submit(paths, "optimize")
    second = masq_requests.submit(paths, "set-mode", payload={"mode": "file"})
    pending = masq_requests.load_pending(paths)
    assert {item.id for item in pending} == {first, second}
    for item in pending:
        masq_requests.discard(item)
    assert masq_requests.load_pending(paths) == []


def test_stale_requests_are_ignored(tmp_path):
    paths = make_paths(tmp_path)
    request_id = masq_requests.submit(paths, "optimize")
    target = paths.request_dir / f"{request_id}.json"
    payload = json.loads(target.read_text(encoding="utf-8"))
    payload["created_at"] = "2020-01-01T00:00:00+00:00"
    target.write_text(json.dumps(payload), encoding="utf-8")
    assert masq_requests.load_pending(paths) == []


def test_oversized_requests_are_ignored(tmp_path):
    paths = make_paths(tmp_path)
    paths.request_dir.mkdir(parents=True, exist_ok=True)
    target = paths.request_dir / "big.json"
    target.write_text(
        json.dumps({"kind": "optimize", "payload": {"x": "y" * 10000}}), encoding="utf-8"
    )
    assert masq_requests.load_pending(paths) == []


def test_malformed_requests_are_ignored(tmp_path):
    paths = make_paths(tmp_path)
    paths.request_dir.mkdir(parents=True, exist_ok=True)
    (paths.request_dir / "a.json").write_text("{not json", encoding="utf-8")
    (paths.request_dir / "b.json").write_text('{"kind": "nope"}', encoding="utf-8")
    assert masq_requests.load_pending(paths) == []


def test_results_are_read_newest_first_and_pruned(tmp_path):
    paths = make_paths(tmp_path)
    ids = []
    for _ in range(masq_requests.MAX_RESULTS + 3):
        request_id = masq_requests.submit(paths, "optimize")
        ids.append(request_id)
        item = [entry for entry in masq_requests.load_pending(paths) if entry.id == request_id][0]
        masq_requests.write_result(paths, item, {"ok": True, "action": "optimize"})
        masq_requests.discard(item)
        time.sleep(0.002)
    results = masq_requests.read_results(paths, limit=50)
    assert 1 <= len(results) <= masq_requests.MAX_RESULTS
    assert all("result" in entry for entry in results)


# --------------------------------------------------------------------------- #
# fallback site
# --------------------------------------------------------------------------- #

def test_site_is_materialised_with_the_server_domain(tmp_path):
    paths = make_paths(tmp_path)
    changed = site_builder.materialize(paths.site_dir, domain="vpn.example.com")
    assert set(changed) == {"index.html", "404.html", "style.css", "favicon.svg"}
    index = (paths.site_dir / "index.html").read_text(encoding="utf-8")
    assert "vpn.example.com" in index
    assert "<html" in index.lower()
    assert "{{DOMAIN}}" not in index


def test_site_has_no_external_dependencies(tmp_path):
    paths = make_paths(tmp_path)
    site_builder.materialize(paths.site_dir, domain="vpn.example.com")
    for name in ("index.html", "404.html", "style.css"):
        text = (paths.site_dir / name).read_text(encoding="utf-8")
        assert "http://" not in text
        assert "https://" not in text
        assert "//cdn" not in text
        assert "@import" not in text


def test_site_is_idempotent(tmp_path):
    paths = make_paths(tmp_path)
    assert site_builder.materialize(paths.site_dir, domain="vpn.example.com")
    assert site_builder.materialize(paths.site_dir, domain="vpn.example.com") == []
    assert site_builder.is_current(paths.site_dir, "vpn.example.com")


def test_changing_the_domain_rewrites_the_site(tmp_path):
    paths = make_paths(tmp_path)
    site_builder.materialize(paths.site_dir, domain="old.example")
    changed = site_builder.materialize(paths.site_dir, domain="new.example")
    assert changed
    assert not site_builder.is_current(paths.site_dir, "old.example")
    assert site_builder.is_current(paths.site_dir, "new.example")


def test_missing_site_is_not_current(tmp_path):
    paths = make_paths(tmp_path)
    assert not site_builder.is_current(paths.site_dir, "vpn.example.com")


def test_site_domain_is_sanitised(tmp_path):
    paths = make_paths(tmp_path)
    site_builder.materialize(paths.site_dir, domain='evil"><script>')
    index = (paths.site_dir / "index.html").read_text(encoding="utf-8")
    assert "<script>" not in index


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX file modes are not enforced on NTFS")
def test_site_files_are_world_readable_but_not_executable(tmp_path):
    paths = make_paths(tmp_path)
    site_builder.materialize(paths.site_dir, domain="vpn.example.com")
    for path in paths.site_dir.iterdir():
        assert path.stat().st_mode & 0o777 == 0o644
