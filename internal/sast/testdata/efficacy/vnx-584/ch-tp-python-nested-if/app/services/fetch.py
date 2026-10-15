import logging

log = logging.getLogger(__name__)


def fetch(session, url):
    try:
        resp = session.get(url)
        resp.raise_for_status()
        return resp.json()
    except ValueError:
        log.warning("bad json")
        raise
    finally:
        session.close()
        if not url:
~>            return {}
