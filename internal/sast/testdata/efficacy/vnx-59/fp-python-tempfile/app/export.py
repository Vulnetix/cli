import os
import tempfile


def export(rows):
    with tempfile.NamedTemporaryFile("w", delete=False, suffix=".csv") as fh:
        fh.writelines(rows)
    fd, name = tempfile.mkstemp(prefix="export-")
    os.close(fd)
    with open("/tmp/report.csv") as fh:
        rows = fh.read()
    with open("/tmp/report.lock", "x") as fh:
        fh.write("1")
    fd = os.open("/tmp/export.lock", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    # open("/tmp/report.csv", "w") would follow a planted symlink
    return name, rows, fd
