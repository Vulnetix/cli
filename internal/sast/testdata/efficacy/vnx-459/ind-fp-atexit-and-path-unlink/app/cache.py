import atexit
import shutil
import tempfile
from pathlib import Path

cache_dir = tempfile.mkdtemp(prefix="app-cache-")
atexit.register(shutil.rmtree, cache_dir, ignore_errors=True)


def stage(data):
    _, staged = tempfile.mkstemp()
    Path(staged).write_bytes(data)
    publish(staged)
    Path(staged).unlink()
