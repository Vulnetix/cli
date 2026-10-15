import os
from tempfile import mkstemp


def export_report(rows, upload):
~>    fd, path = mkstemp(suffix=".csv")
    with os.fdopen(fd, "w") as fh:
        for row in rows:
            fh.write(",".join(row) + "\n")
    upload(path)
