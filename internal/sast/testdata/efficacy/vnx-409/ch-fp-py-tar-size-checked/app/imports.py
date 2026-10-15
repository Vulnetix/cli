import tarfile

MAX_TOTAL = 200 * 1024 * 1024


def import_bundle(path, dest):
    with tarfile.open(path) as tar:
        members = tar.getmembers()
        if sum(m.size for m in members) > MAX_TOTAL:
            raise ValueError("archive too large")
        tar.extractall(dest, filter="data")
