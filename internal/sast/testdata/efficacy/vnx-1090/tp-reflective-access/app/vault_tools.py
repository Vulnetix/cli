import logging

log = logging.getLogger(__name__)


def peek(vault):
~>    return getattr(vault, "_Vault__master_key")


def rotate(vault, new_key):
~>    setattr(vault, '_Vault__master_key', new_key)
    log.info("rotated")


def is_sealed(vault):
~>    return hasattr( vault , "_Vault__sealed" )
