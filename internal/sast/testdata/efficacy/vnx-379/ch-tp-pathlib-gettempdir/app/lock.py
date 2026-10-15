import tempfile
from pathlib import Path


def acquire(pid: int) -> Path:
~>    lock = Path(tempfile.gettempdir()) / "worker.lock"
    lock.write_text(str(pid))
    return lock


def marker():
~>    Path("/var/tmp/app-ready").touch()
