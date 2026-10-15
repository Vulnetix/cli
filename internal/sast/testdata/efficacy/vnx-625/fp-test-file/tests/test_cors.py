import re


def test_origin():
    assert re.match(r"^https://app.example.com", "https://app.example.com")
