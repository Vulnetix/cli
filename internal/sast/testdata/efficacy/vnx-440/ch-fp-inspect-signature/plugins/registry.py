import inspect
from inspect import signature


def register(handler):
    assert inspect.signature(handler).parameters, "handler takes arguments"
    assert len(signature(handler).parameters) == 2
    assert callable(handler)
    _HANDLERS.append(handler)
