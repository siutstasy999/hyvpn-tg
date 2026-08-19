from bot.i18n import (
    COMMAND_DESCRIPTIONS,
    LANG_LABELS,
    LANGS,
    TEXTS,
    normalize_lang,
    parse_size,
    t,
)


def test_every_language_defines_the_same_keys():
    reference = set(TEXTS["ru"])
    for lang in LANGS:
        assert lang in TEXTS, f"missing catalog: {lang}"
        missing = reference - set(TEXTS[lang])
        extra = set(TEXTS[lang]) - reference
        assert not missing, f"{lang} is missing: {sorted(missing)}"
        assert not extra, f"{lang} has unknown keys: {sorted(extra)}"
        assert lang in LANG_LABELS
        assert set(COMMAND_DESCRIPTIONS[lang]) == set(COMMAND_DESCRIPTIONS["ru"])


def test_placeholders_match_between_languages():
    import re

    placeholder = re.compile(r"\{(\w+)\}")
    for key, template in TEXTS["ru"].items():
        expected = set(placeholder.findall(template))
        for lang in LANGS:
            found = set(placeholder.findall(TEXTS[lang][key]))
            assert found == expected, f"{lang}.{key}: {found} != {expected}"


def test_normalize_lang():
    assert normalize_lang(None) == "ru"
    assert normalize_lang("en") == "en"
    assert normalize_lang("EN-US") == "en"
    assert normalize_lang("de") == "ru"  # unsupported falls back


def test_translation_lookup_and_fallback():
    assert t("en", "btn_menu") == "🏠 Menu"
    assert t("ru", "btn_menu") == "🏠 Меню"
    # Unknown keys return the key itself instead of raising.
    assert t("en", "no_such_key") == "no_such_key"
    # Missing kwargs must not crash a live bot.
    assert "{" in t("en", "menu_keys")


def test_parse_size():
    gib = 1024**3
    assert parse_size("50 GB") == 50 * gib
    assert parse_size("50gb") == 50 * gib
    assert parse_size("50") == 50 * gib  # bare numbers are gigabytes
    assert parse_size("1.5tb") == int(1.5 * 1024**4)
    assert parse_size("1,5 ТБ") == int(1.5 * 1024**4)
    assert parse_size("500mb") == 500 * 1024**2
    assert parse_size("2048") == 2048 * gib
    assert parse_size("1024 b") == 1024

    # Unlimited
    assert parse_size("0") == 0
    assert parse_size("unlimited") == 0
    assert parse_size("без лимита") is None  # two words: not a size
    assert parse_size("безлимит") == 0
    assert parse_size("-") == 0

    # Invalid
    assert parse_size("") is None
    assert parse_size(None) is None
    assert parse_size("много") is None
    assert parse_size("50 zb") is None
    assert parse_size("-5gb") is None
