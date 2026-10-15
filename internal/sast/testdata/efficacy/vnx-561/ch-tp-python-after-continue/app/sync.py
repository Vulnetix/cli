import logging

log = logging.getLogger(__name__)


def sync(items):
    for item in items:
        if not item.enabled:
            continue
~>            log.debug("skipped %s", item.id)
        push(item)


def close(conn):
    raise ConnectionError("closed")
~>    audit("close", conn)
