from hashlib import md5 as _md5
from pathlib import Path


def build_manifest(root: Path) -> dict:
    manifest = {}
    for path in sorted(root.rglob("*")):
        if path.is_file():
~>            manifest[str(path.relative_to(root))] = _md5(path.read_bytes()).hexdigest()
    return manifest
