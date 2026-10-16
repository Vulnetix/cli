import csv


def dump(rows, path="/var/backups/users.csv"):
    with open(path, "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerows(rows)
