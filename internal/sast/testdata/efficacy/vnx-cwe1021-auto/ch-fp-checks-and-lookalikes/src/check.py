import logging

log = logging.getLogger(__name__)


def check(resp):
    if resp.headers.get("X-Frame-Options") == "ALLOWALL":
        log.warning("response allows framing: X-Frame-Options ALLOWALL")
    if resp.headers['X-Frame-Options'] == 'ALLOW-FROM':
        return False
    return True
