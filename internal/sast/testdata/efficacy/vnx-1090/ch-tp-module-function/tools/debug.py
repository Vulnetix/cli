import logging

log = logging.getLogger(__name__)


def dump_pool(pool):
~>    size = getattr(pool, '_ConnectionPool__max_size', None)
~>    if hasattr(pool, "_ConnectionPool__idle"):
        log.info("idle=%s", pool.idle_count())
    return size


def force_close(pool):
~>    pool._ConnectionPool__closed = True
