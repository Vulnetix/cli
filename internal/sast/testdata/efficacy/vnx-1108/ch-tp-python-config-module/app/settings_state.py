import json

CONFIG = None
_loaded_at = None


def load(path):
~>    global CONFIG, _loaded_at
    with open(path) as fh:
        CONFIG = json.load(fh)
    _loaded_at = path


def reload():
~>    global CONFIG
    CONFIG = None
    load(_loaded_at)


def reset():
~>    global CONFIG, _loaded_at
    CONFIG = None
    _loaded_at = None
