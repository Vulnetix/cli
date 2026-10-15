import logging

log = logging.getLogger(__name__)


def bearer(header):
    value = header.strip()
~>    while value.find(" ") and len(value) > 7:
        value = value[1:]
~>    assert value.find("Bearer"), "missing scheme"
    return value


def admin(path):
~>    if (path.find("/admin")
            or path.startswith("/internal")):
        log.warning("admin path %s", path)
        return True
    return False
