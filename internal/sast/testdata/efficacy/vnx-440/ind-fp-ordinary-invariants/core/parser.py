import inspect


def parse(tokens):
    token = tokens.pop(0)
    assert token.type == "NAME"
    assert isinstance(tokens, list)
    assert len(tokens) >= 0, "password list must not be negative"
    return token


def register(fn):
    assert "request" in inspect.signature(fn).parameters
    return fn


def unreachable():
    raise AssertionError("unreachable")
