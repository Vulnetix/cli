import os
from pathlib import Path


def write_key(key_path: Path, material: bytes):
    if not key_path.exists():
~>        key_path.write_bytes(material)


def lock_down(secret_file):
    if os.path.exists(secret_file):
~>        os.chmod(secret_file, 0o600)
