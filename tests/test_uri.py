from urllib.parse import unquote, urlsplit

from core.uri import build_uri, clean_name


def test_profile_name_stays_human_readable():
    uri = build_uri("secret", "my-own.online", 443, "🇫🇮 Finland")
    # The fragment is what the client shows: no percent-encoded bytes.
    assert uri.endswith("#🇫🇮 Finland")
    assert "%" not in uri.split("#", 1)[1]


def test_key_label_is_not_part_of_the_uri():
    uri = build_uri("secret", "my-own.online", 443, "Finland")
    assert "Finland" in uri
    for label in ("Ivan", "iPhone", "Я"):
        assert label not in uri


def test_fragment_falls_back_to_domain():
    assert build_uri("secret", "my-own.online").endswith("#my-own.online")
    assert build_uri("secret", "my-own.online", 443, "   ").endswith("#my-own.online")


def test_password_is_percent_encoded():
    uri = build_uri("a/b c+d", "my-own.online", 443, "Finland")
    parts = urlsplit(uri)
    assert parts.scheme == "hysteria2"
    assert "/" not in parts.netloc.split("@")[0]
    assert unquote(parts.netloc.split("@")[0]) == "a/b c+d"


def test_generated_passwords_need_no_escaping():
    from core.keys_service import generate_password

    for _ in range(20):
        password = generate_password()
        assert "%" not in build_uri(password, "my-own.online").split("@")[0]


def test_uri_shape():
    uri = build_uri("pw", "my-own.online", 8443, "Finland")
    assert uri == "hysteria2://pw@my-own.online:8443/?sni=my-own.online#Finland"


def test_clean_name():
    assert clean_name("  a\n\tb  ") == "a b"
    assert clean_name("a" + chr(0) + "b") == "a b"
    assert clean_name(None) == ""
    assert len(clean_name("x" * 200)) == 64
