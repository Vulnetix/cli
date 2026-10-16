import os
import tempfile


def stage(data: bytes) -> str:
    fd, path = tempfile.mkstemp(suffix=".bin")
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)
    return path


def stage_named(data: bytes):
    with tempfile.NamedTemporaryFile(dir="/tmp", delete=False) as fh:
        fh.write(data)
        return fh.name


def build():
    with tempfile.TemporaryDirectory(prefix="build-") as d:
        with open(os.path.join(d, "out.txt"), "w") as fh:
            fh.write("ok")
