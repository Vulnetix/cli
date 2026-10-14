import contextlib
import errno
import logging
import os
import stat
from pathlib import Path

logger = logging.getLogger(__name__)


def save_token(path, token):
    with open(path, "w") as fh:
        fh.write(token)
    try:
~>        Path(path).chmod(stat.S_IRUSR | stat.S_IWUSR)
    except Exception as exc:  # noqa: BLE001
        logger.debug("chmod failed: %s", exc)


def save_key(path, key):
    path.write_bytes(key)
    with contextlib.suppress(OSError):
~>        os.chmod(path, 0o400)


def socket_dir():
    sock_dir = "/run/app"
    try:
        os.makedirs(sock_dir, exist_ok=True)
    except OSError as e:
        if e.errno == errno.EACCES:
~>            sock_dir = "/tmp"
    return sock_dir
