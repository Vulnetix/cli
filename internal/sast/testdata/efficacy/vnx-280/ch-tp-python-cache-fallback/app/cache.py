import os
import tempfile
from pathlib import Path


def cache_dir():
    base = Path("/var/cache/app")
    try:
        base.mkdir(parents=True, exist_ok=True)
    except PermissionError:
~>        base = Path(tempfile.gettempdir()) / "app-cache"
        base.mkdir(exist_ok=True)
    return base
