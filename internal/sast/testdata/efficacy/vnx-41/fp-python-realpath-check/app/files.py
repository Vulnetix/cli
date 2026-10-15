import os
from pathlib import Path

UPLOAD_DIR = os.path.realpath("/srv/uploads")
BASE = Path("/srv/reports").resolve()


def download(name):
    full = os.path.realpath(os.path.join(UPLOAD_DIR, name))
    if not full.startswith(UPLOAD_DIR + os.sep):
        raise PermissionError(name)
    return full


def preview(name):
    full = os.path.join(UPLOAD_DIR, name)
    full = os.path.abspath(full)
    if full.startswith(UPLOAD_DIR):
        return full


def report(name):
    target = (BASE / name).resolve()
    if not target.is_relative_to(BASE):
        raise PermissionError(name)
    return target
