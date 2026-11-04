"""Rendering and validating the masquerade section of the server config."""

from __future__ import annotations

import pytest

from core.masquerade.config import MasqConfig
from core.masquerade.render import (
    describe_masquerade,
    effective_mode_of,
    render_fragment,
    validate_masquerade,
    validate_runtime_config,
)
from tests.masq_fakes import TEMPLATE

DOMAIN = "vpn.example.com"


def parse(fragment: str) -> dict:
    import yaml

    return yaml.safe_load(fragment) or {}


def base_config(**overrides) -> MasqConfig:
    values = {
        "mode": "auto",
        "string_content": "<!doctype html><html><body>hello</body></html>",
        "string_headers": {"content-type": "text/html; charset=utf-8"},
        "string_status_code": 200,
    }
    values.update(overrides)
    return MasqConfig(**values)


# --------------------------------------------------------------------------- #
# fragment rendering
# --------------------------------------------------------------------------- #

def test_proxy_fragment_uses_only_documented_fields():
    fragment = render_fragment(
        "proxy",
        base_config(),
        upstream_url="https://origin.example/",
        runtime_config="/run/hyvpn/hysteria-server.yaml",
    )
    payload = parse(fragment)
    assert payload == {
        "masquerade": {
            "type": "proxy",
            "proxy": {
                "url": "https://origin.example/",
                "rewriteHost": True,
                "insecure": False,
                "xForwarded": False,
            },
        }
    }
    assert fragment.startswith("# Managed by `hyvpn masquerade`")


def test_proxy_fragment_never_enables_insecure():
    config = base_config(x_forwarded=True, rewrite_host=False)
    payload = parse(
        render_fragment("proxy", config, upstream_url="https://origin.example/")
    )
    proxy = payload["masquerade"]["proxy"]
    assert proxy["insecure"] is False
    assert proxy["xForwarded"] is True
    assert proxy["rewriteHost"] is False


def test_file_fragment_points_at_the_managed_site():
    payload = parse(
        render_fragment("file", base_config(), site_dir="/var/lib/hyvpn/masquerade/site")
    )
    assert payload["masquerade"] == {
        "type": "file",
        "file": {"dir": "/var/lib/hyvpn/masquerade/site"},
    }


def test_string_fragment_carries_status_and_headers():
    payload = parse(render_fragment("string", base_config()))
    string = payload["masquerade"]["string"]
    assert string["statusCode"] == 200
    assert string["headers"] == {"content-type": "text/html; charset=utf-8"}
    assert "hello" in string["content"]


def test_none_mode_omits_the_section_entirely():
    fragment = render_fragment("none", base_config())
    assert "masquerade:" not in fragment
    assert parse(fragment) == {}
    assert effective_mode_of(fragment) == "none"


def test_proxy_mode_without_an_upstream_is_refused():
    with pytest.raises(ValueError):
        render_fragment("proxy", base_config(), upstream_url=None)


def test_unknown_mode_is_refused():
    with pytest.raises(ValueError):
        render_fragment("carrier-pigeon", base_config())


def test_describe_flattens_the_section():
    section = parse(
        render_fragment("proxy", base_config(), upstream_url="https://origin.example/")
    )["masquerade"]
    described = describe_masquerade(section)
    assert described["mode"] == "proxy"
    assert described["upstream"] == "https://origin.example/"
    assert described["insecure"] is False
    assert describe_masquerade(None)["mode"] == "none"


# --------------------------------------------------------------------------- #
# masquerade schema validation
# --------------------------------------------------------------------------- #

def test_valid_proxy_section_passes():
    result = validate_masquerade(
        {
            "type": "proxy",
            "proxy": {
                "url": "https://origin.example/",
                "rewriteHost": True,
                "insecure": False,
                "xForwarded": False,
            },
        },
        expected_mode="proxy",
    )
    assert result.ok


def test_unknown_field_is_rejected():
    result = validate_masquerade(
        {"type": "proxy", "proxy": {"url": "https://origin.example/", "sni": "google.com"}}
    )
    assert not result.ok
    assert any("sni" in error for error in result.errors)


def test_insecure_upstream_is_rejected():
    result = validate_masquerade(
        {
            "type": "proxy",
            "proxy": {"url": "https://origin.example/", "insecure": True},
        }
    )
    assert not result.ok
    assert any("insecure" in error for error in result.errors)


def test_http_upstream_is_rejected():
    result = validate_masquerade(
        {"type": "proxy", "proxy": {"url": "http://origin.example/"}}
    )
    assert not result.ok
    assert any("https" in error for error in result.errors)


def test_section_for_another_type_is_rejected():
    result = validate_masquerade(
        {
            "type": "file",
            "file": {"dir": "/tmp"},
            "proxy": {"url": "https://origin.example/"},
        }
    )
    assert not result.ok
    assert any("only the selected sub-section" in error for error in result.errors)


def test_missing_section_when_a_mode_was_requested_is_an_error():
    assert validate_masquerade(None, expected_mode="file").ok is False
    assert validate_masquerade(None, expected_mode="none").ok is True


def test_file_mode_without_index_is_an_error(tmp_path):
    (tmp_path / "elsewhere").mkdir()
    result = validate_masquerade(
        {"type": "file", "file": {"dir": str(tmp_path / "elsewhere")}}
    )
    assert not result.ok
    assert any("index.html" in error for error in result.errors)


def test_file_mode_with_a_missing_directory_is_only_a_warning(tmp_path):
    result = validate_masquerade(
        {"type": "file", "file": {"dir": str(tmp_path / "not-yet")}}
    )
    assert result.ok
    assert any("does not exist yet" in warning for warning in result.warnings)


def test_empty_string_content_is_rejected():
    result = validate_masquerade({"type": "string", "string": {"content": "  "}})
    assert not result.ok


def test_string_status_code_is_range_checked():
    result = validate_masquerade(
        {"type": "string", "string": {"content": "hi", "statusCode": 900}}
    )
    assert not result.ok


def test_unknown_type_is_rejected():
    result = validate_masquerade({"type": "reality"})
    assert not result.ok
    assert any("masquerade.type" in error for error in result.errors)


# --------------------------------------------------------------------------- #
# whole runtime configuration
# --------------------------------------------------------------------------- #

def rendered(fragment: str) -> str:
    from core.hysteria_config import render

    return render(
        TEMPLATE,
        {
            "ACME_DOMAIN": DOMAIN,
            "ACME_EMAIL": "admin@example.com",
            "TRAFFIC_STATS_SECRET": "secret",
        },
        fragment,
    )


def test_complete_rendered_config_passes(tmp_path):
    site = tmp_path / "site"
    site.mkdir()
    (site / "index.html").write_text("<!doctype html><html></html>", encoding="utf-8")
    fragment = render_fragment("file", base_config(), site_dir=str(site))
    result = validate_runtime_config(
        rendered(fragment), domain=DOMAIN, expected_mode="file"
    )
    assert result.ok, result.errors


def test_file_mode_without_a_real_index_fails_the_whole_config(tmp_path):
    site = tmp_path / "empty-site"
    site.mkdir()
    fragment = render_fragment("file", base_config(), site_dir=str(site))
    result = validate_runtime_config(
        rendered(fragment), domain=DOMAIN, expected_mode="file"
    )
    assert not result.ok
    assert any("index.html" in error for error in result.errors)


def test_sni_guard_disable_is_rejected():
    text = rendered(render_fragment("file", base_config(), site_dir="/tmp")).replace(
        "trafficStats:", "sniGuard: disable\ntrafficStats:"
    )
    result = validate_runtime_config(text, domain=DOMAIN)
    assert not result.ok
    assert any("sniGuard" in error for error in result.errors)


def test_acme_domains_must_contain_the_server_domain():
    text = rendered(render_fragment("none", base_config())).replace(
        DOMAIN, "elsewhere.example"
    )
    result = validate_runtime_config(text, domain=DOMAIN)
    assert not result.ok
    assert any("does not contain" in error for error in result.errors)


def test_invalid_yaml_is_reported():
    result = validate_runtime_config("listen: :443\n  bad indent: [", domain=DOMAIN)
    assert not result.ok
    assert any("not valid YAML" in error for error in result.errors)


def test_missing_listen_is_reported():
    text = "acme:\n  domains:\n    - vpn.example.com\n"
    result = validate_runtime_config(text, domain=DOMAIN)
    assert not result.ok
    assert any("listen" in error for error in result.errors)


def test_tls_insecure_is_rejected():
    text = (
        "listen: :443\n"
        "tls:\n  cert: a.crt\n  key: a.key\n  insecure: true\n"
    )
    result = validate_runtime_config(text, domain=DOMAIN)
    assert not result.ok
    assert any("tls.insecure" in error for error in result.errors)


def test_masquerade_section_is_validated_as_part_of_the_whole():
    text = rendered(
        "masquerade:\n  type: proxy\n  proxy:\n    url: http://origin.example/\n"
    )
    result = validate_runtime_config(text, domain=DOMAIN, expected_mode="proxy")
    assert not result.ok
    assert any("https" in error for error in result.errors)


def test_expected_mode_mismatch_is_detected():
    result = validate_runtime_config(
        rendered(render_fragment("file", base_config(), site_dir="/tmp")),
        domain=DOMAIN,
        expected_mode="proxy",
    )
    assert not result.ok
    assert any("requested" in error for error in result.errors)


def test_config_user_error_message_mentions_the_file(tmp_path):
    from core.masquerade.config import ConfigError, load_config
    from tests.masq_fakes import make_paths

    paths = make_paths(tmp_path)
    paths.config.parent.mkdir(parents=True, exist_ok=True)
    paths.config.write_text("{not json", encoding="utf-8")
    with pytest.raises(ConfigError) as excinfo:
        load_config(paths)
    assert "masquerade.json" in str(excinfo.value)
