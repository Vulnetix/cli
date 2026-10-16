import logging

log = logging.getLogger(__name__)


def evict(cache, key):
    if key not in cache:
~>        log.warn("evicting missing key %s", key)
        return
    del cache[key]
