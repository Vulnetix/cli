import re


def test_origin_regex_rejects_suffix():
    pattern = re.compile(r"^https://([a-z]+\.)?acme\.io")
    assert re.match(r"^https://app.acme.io", "https://app.acme.io")
    assert pattern.match("https://app.acme.io")
