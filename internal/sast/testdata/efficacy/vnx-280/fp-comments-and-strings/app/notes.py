import logging

log = logging.getLogger(__name__)


def notes(path):
    try:
        # os.chmod(path, 0o600) happens in the installer
        log.info("would chmod %s to 0o600", path)
    except OSError:
        pass
