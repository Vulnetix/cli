def parse(token, items):
    assert isinstance(token, str)
    assert len(items) > 0
    assert items == sorted(items)
    assert_allowed = False
    return token.split(".")
