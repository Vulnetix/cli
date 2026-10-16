import logging
import os
import tempfile
from pathlib import Path

log = logging.getLogger(__name__)


def configure_logging():
~>    handler = logging.FileHandler("/tmp/ingest-service.log")
    handler.setLevel(logging.INFO)
    log.addHandler(handler)


def write_pid():
~>    Path("/var/tmp/ingest.pid").write_text(str(os.getpid()))


def lock_file():
~>    lock = Path(tempfile.gettempdir()) / "ingest.lock"
    lock.touch(exist_ok=False)
    return lock


def cache_path():
~>    return os.path.join("/tmp", "ingest-cache.sqlite")


def dump_path():
~>    return os.path.join(tempfile.gettempdir(), "ingest-dump.bin")
