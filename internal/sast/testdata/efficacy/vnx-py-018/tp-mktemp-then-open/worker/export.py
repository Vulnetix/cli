import os
import tempfile


def export_report(data: bytes) -> str:
~>    path = tempfile.mktemp(suffix=".csv")
    with open(path, "wb") as fh:
        fh.write(data)
    return path


def scratch_dir():
~>    return tempfile.mktemp(prefix="job-", dir="/tmp")
