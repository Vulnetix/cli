import logging

log = logging.getLogger(__name__)


def describe(obj):
    name = obj.__class__.__name__
    fields = sorted(obj.__dict__)
    log.debug("private state lives in obj._Registry__items; use obj.items() instead")
    return f"{name}: {fields}"


def module_of(cls):
    return cls.__module__
