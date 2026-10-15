from calc import parse


def test_parse_exact():
    assert parse("0.1") == 0.1
