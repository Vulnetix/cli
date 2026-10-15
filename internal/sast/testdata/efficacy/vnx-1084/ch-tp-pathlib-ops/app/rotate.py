import os
import shutil
from pathlib import Path


~>def rotate(base: Path):
    base.mkdir(parents=True, exist_ok=True)
    old = base / "app.log.2"
    old.unlink(missing_ok=True)
    os.rename(base / "app.log.1", old)
    shutil.move(base / "app.log", base / "app.log.1")
    (base / "app.log").touch()
    (base / "tmp").rmdir()
    (base / "state").write_text("rotated")
    marker = (base / "marker").read_bytes()
    return marker
