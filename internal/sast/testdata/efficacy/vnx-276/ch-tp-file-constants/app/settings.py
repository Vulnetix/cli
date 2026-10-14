"""Runtime settings for the spooler."""

import os

SPOOL_MODE = 0o777
LOG_MODE = 0o640

# The spooler writes jobs here; the printer daemon runs as another user and
# removes them when printed.
SPOOL_DIR = "/var/spool/app"
LOG_DIR = "/var/log/app"


def _ensure(path):
    os.makedirs(path, exist_ok=True)


def prepare():
    _ensure(SPOOL_DIR)
    _ensure(LOG_DIR)
    # the daemon must be able to delete finished jobs
~>    os.chmod(SPOOL_DIR, SPOOL_MODE)
    os.chmod(LOG_DIR, LOG_MODE)
