import os
import shutil
from pathlib import Path


~>async def rotate_logs(base):
    os.makedirs(f"{base}/archive", exist_ok=True)
    shutil.copy(f"{base}/app.log", f"{base}/archive/app.log.1")
    os.remove(f"{base}/app.log")
    Path(f"{base}/app.log").write_text("")
    os.rename(f"{base}/err.log", f"{base}/archive/err.log.1")
    shutil.move(f"{base}/access.log", f"{base}/archive/access.log.1")
    os.unlink(f"{base}/lock")
    shutil.rmtree(f"{base}/tmp")
    stamp = Path(f"{base}/stamp").read_text()
    return stamp
