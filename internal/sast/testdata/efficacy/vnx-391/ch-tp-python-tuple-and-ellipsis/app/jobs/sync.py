import logging

log = logging.getLogger(__name__)


def push(batch, client):
    for item in batch:
        try:
            client.send(item)
~>        except (ValueError, Exception) as exc:
            pass


def warm(cache):
    try:
        cache.prime()
~>    except BaseException:
        ...


def close(conn):
    try: conn.close()
~>    except: pass
