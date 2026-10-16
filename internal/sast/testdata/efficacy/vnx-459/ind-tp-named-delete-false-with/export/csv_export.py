import csv
import tempfile


def export_rows(rows, uploader):
~>    with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False, newline="") as fh:
        writer = csv.writer(fh)
        writer.writerows(rows)
    uploader.upload(fh.name)
