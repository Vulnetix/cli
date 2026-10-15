"""Plugin registry."""

global REGISTRY
REGISTRY = {}

HELP = "Avoid 'global a, b, c, d' in plugins; use register() instead."

_loaded = None


def load():
    global _loaded
    if _loaded is None:
        _loaded = dict(REGISTRY)
    return _loaded


def register(name, fn):
    # global REGISTRY is not needed: we mutate, not rebind
    REGISTRY[name] = fn
