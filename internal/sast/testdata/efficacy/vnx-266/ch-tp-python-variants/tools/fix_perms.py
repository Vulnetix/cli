from os import chmod
from pathlib import Path


def fix(path):
~>    chmod(path, 0o6755)


def fix_path(p: Path):
~>    p.chmod(0o4755)
    p.with_suffix(".log").chmod(0o644)
