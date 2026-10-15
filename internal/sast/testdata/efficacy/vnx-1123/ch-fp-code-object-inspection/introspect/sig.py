import types


def same_body(a, b):
    return a.__code__ == b.__code__


def arity(fn):
    return fn.__code__.co_argcount


def is_code(obj: types.CodeType) -> bool:
    return isinstance(obj, types.CodeType)
