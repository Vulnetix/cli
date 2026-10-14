from . import (
    config,
    plugins,
)

_OVERRIDES = {}


def overrides():
    return dict(_OVERRIDES)


def debug_enabled():
    return config.load()["debug"]
