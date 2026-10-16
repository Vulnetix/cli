try:
    import ujson as json
except ImportError:
    import json

try:
    from functools import cache
except ImportError:
    pass


def lookup(table, key):
    try:
        return table[key]
    except KeyError:
        pass
    return None
