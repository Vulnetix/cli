import types


def swap(target, replacement):
~>    target.__code__ = replacement.__code__


def rebuild(fn, new_bytes):
~>    return fn.__code__.replace(
        co_code=new_bytes,
    )
