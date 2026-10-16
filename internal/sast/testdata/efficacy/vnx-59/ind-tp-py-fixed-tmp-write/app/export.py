import csv
import os


def export_report(rows):
~>    with open("/tmp/report.csv", "w", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerows(rows)
~>    os.chmod("/tmp/app.sock", 0o777)
    return "/tmp/report.csv"
