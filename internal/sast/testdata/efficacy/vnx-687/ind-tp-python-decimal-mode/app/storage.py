import os
from pathlib import Path


def prepare(base: str) -> Path:
~>    os.makedirs(base, 755, exist_ok=True)
    run = Path(base, "run")
~>    run.mkdir(mode=700)
    return run
