import logging

log = logging.getLogger(__name__)

# never call os.chmod(path, 0o777) on uploads
# os.umask(0)
def warn():
    log.warning("refusing os.chmod(path, 0o777)")
    hint = 'os.umask(0) makes files world-writable'
    return hint
