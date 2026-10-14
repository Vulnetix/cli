import os
import tarfile


def _safe_members(tar, dest):
    base = os.path.realpath(dest)
    for member in tar.getmembers():
        target = os.path.realpath(os.path.join(dest, member.name))
        if os.path.commonpath([base, target]) == base and not member.issym():
            yield member


def load(archive, dest):
    with tarfile.open(archive) as tar:
        tar.extractall(dest, members=_safe_members(tar, dest))


def load_checked(archive, dest):
    with tarfile.open(archive) as tar:
        for member in tar.getmembers():
            if member.name.startswith("/") or ".." in member.name:
                raise ValueError(f"unsafe path {member.name}")
        tar.extractall(dest)
