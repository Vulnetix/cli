import json
import os


def load_cache(path):
    try:
        with open(path) as fh:
            return json.load(fh)
~>    except:
        pass
    return {}


def purge(path):
    try:
        os.remove(path)
~>    except Exception:
        pass


def warm(keys, store):
    for key in keys:
        try:
            store.fetch(key)
~>        except BaseException as exc:
            ...
