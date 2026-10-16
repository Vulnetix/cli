import os
import shutil
from pathlib import Path


~>def rotate(root, new):
    os.makedirs(root / "releases", exist_ok=True)
    shutil.copytree(new, root / "releases" / "next")
    os.rename(root / "current", root / "previous")
    os.replace(root / "releases" / "next", root / "current")
    shutil.rmtree(root / "previous")
    Path(root / "DEPLOYED").touch()
    (root / "log.txt").write_text("rotated")
    os.remove(root / "lock")
    shutil.move(str(root / "tmp"), str(root / "old"))
