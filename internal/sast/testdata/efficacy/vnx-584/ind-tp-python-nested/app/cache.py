import logging

log = logging.getLogger(__name__)


def fetch_profile(client, user_id, cache=None):
    try:
        profile = client.get(f"/users/{user_id}")
        profile.raise_for_status()
        return profile.json()
    except Exception:
        log.exception("profile fetch failed")
        raise
    finally:
        client.close()
        if cache is not None:
~>            return cache.get(user_id)


def flush(queue):
    try:
        queue.drain()
    finally:
~>        return queue.size()
