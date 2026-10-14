import contextlib
import logging
import os
from pathlib import Path

log = logging.getLogger(__name__)


def write_token(path, token):
    with open(path, "w") as handle:
        try:
~>            os.chmod(path, 0o600)
        except OSError:
            pass
        handle.write(token)


def write_key(path, key):
    with contextlib.suppress(PermissionError):
~>        Path(path).chmod(0o600)
    Path(path).write_text(key)


def lock_config(path):
    try:
~>        os.chmod(path, 0o400)
    except PermissionError as exc:
        log.warning("could not restrict %s: %s", path, exc)
