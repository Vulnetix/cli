import tarfile

# Do not call tar.extractall(dest) on uploads without filter="data".
ADVICE = "tarfile.open(p).extractall(d) is unsafe"


def members(path):
    with tarfile.open(path) as tar:
        return [m.name for m in tar.getmembers()]


def read_one(path, name):
    with tarfile.open(path) as tar:
        return tar.extractfile(name).read()
