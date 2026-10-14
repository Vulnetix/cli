import os
import stat
from pathlib import Path

UPLOAD_DIR = Path("/srv/app/uploads")


def prepare():
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
~>    UPLOAD_DIR.chmod(0o777)
~>    os.chmod(
        "/srv/app/cache",
        stat.S_IRWXU | stat.S_IRWXG | stat.S_IRWXO,
    )
