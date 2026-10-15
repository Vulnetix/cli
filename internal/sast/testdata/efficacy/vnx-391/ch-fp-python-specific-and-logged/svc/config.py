import logging
import os

log = logging.getLogger(__name__)

try:
    import ujson as json
except ImportError:
    import json


def read(path):
    try:
        with open(path) as fh:
            return json.load(fh)
    except FileNotFoundError:
        pass
    except Exception:
        log.exception("could not read %s", path)
        raise
    return {}


def env_int(name):
    try:
        return int(os.environ[name])
    except (KeyError, ValueError):
        return None


HELP = """
try:
    risky()
except Exception:
    pass
"""
