import types


def target():
    return 1


def mutate(fn, other):
~>    fn.__code__ = other.__code__
~>    co = fn.__code__.replace(co_code=bytes([100, 1, 83, 0]))
~>    fresh = types.CodeType(0, 0, 0, 0, 0, 0, co.co_code, (), (), (), "", "", 1, b"")
    return co, fresh
