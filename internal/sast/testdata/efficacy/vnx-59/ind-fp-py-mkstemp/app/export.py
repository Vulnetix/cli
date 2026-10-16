import csv
import os
import tempfile


def export_report(rows):
    fd, path = tempfile.mkstemp(suffix=".csv")
    with os.fdopen(fd, "w", newline="") as fh:
        csv.writer(fh).writerows(rows)
    return path


def export_named(rows):
    with tempfile.NamedTemporaryFile("w", suffix=".csv", delete=False) as fh:
        csv.writer(fh).writerows(rows)
        return fh.name


def export_to_home(rows):
    out = os.path.expanduser("~/.local/share/app/report.csv")
    with open(out, "w") as fh:
        csv.writer(fh).writerows(rows)
