import logging

log = logging.getLogger(__name__)


def rotate(vault, new_key):
    log.info("rotating key for %s", vault.name)
~>    setattr(vault, "_Vault__master_key", new_key)
    return vault


def peek(vault):
~>    return getattr(vault, '_Vault__master_key', None)
