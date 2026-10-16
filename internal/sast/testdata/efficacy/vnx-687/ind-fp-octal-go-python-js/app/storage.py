import os
import stat
from pathlib import Path


def prepare(base: str) -> None:
    os.makedirs(base, 0o755, exist_ok=True)
    Path(base, "run").mkdir(mode=0o700)
    os.chmod(base, stat.S_IRWXU)
