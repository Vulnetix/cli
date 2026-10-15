import logging

log = logging.getLogger(__name__)

try:
    import ujson as json
except ImportError:
    import json


def parse(raw):
    try:
        return json.loads(raw)
    except Exception:
        log.exception("bad payload")
        raise


def lookup(d, key):
    try:
        return d[key]
    except KeyError:
        pass
    return None


def cleanup(path):
    try:
        path.unlink()
    except Exception:
        # the temp dir is reaped by the OS on reboot; a stale file is harmless
        pass


def safe(fn):
    try:
        fn()
    except Exception as exc:
        log.warning("failed: %s", exc)
