from pathlib import Path
import csv


def write_report(rows, out_dir="/var/lib/app/reports"):
    out = Path(out_dir) / "daily.csv"
    with out.open("w", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerows(rows)
~>    out.chmod(0o666)
    return out
