import os
import tempfile
from pathlib import Path


def export(rows, user):
~>    with open("/tmp/report.csv", "w") as fh:
        fh.writelines(rows)
~>    with open(f"/tmp/{user}.json", "a", encoding="utf-8") as fh:
        fh.write("{}")
~>    fd = os.open("/tmp/export.lock", os.O_WRONLY | os.O_CREAT)
    os.close(fd)


def cache(data):
    path = os.path.join(tempfile.gettempdir(), "cache.db")
~>    with open(path, "wb") as fh:
        fh.write(data)
~>    Path("/tmp/out.txt").write_text(data.decode())
~>    os.chmod("/tmp/app.sock", 0o777)
