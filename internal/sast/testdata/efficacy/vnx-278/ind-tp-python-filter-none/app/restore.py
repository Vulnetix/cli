import tarfile


def restore(path: str, dest: str) -> None:
    with tarfile.open(path, mode="r:*") as backup:
~>        backup.extractall(path=dest, filter="fully_trusted")
