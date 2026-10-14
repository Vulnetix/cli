import os
import tempfile


def export_report(data: bytes) -> str:
    fd, path = tempfile.mkstemp(suffix=".csv")
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)
    return path


def staging():
    with tempfile.NamedTemporaryFile(delete=False) as fh:
        return fh.name


def workdir():
    return tempfile.mkdtemp(prefix="job-")


def tdir():
    with tempfile.TemporaryDirectory() as d:
        return d
