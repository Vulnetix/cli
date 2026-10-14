import os
~>import core.registry as registry

DEFAULTS = {"debug": False}


def load():
    values = dict(DEFAULTS)
    values.update(registry.overrides())
    return values
