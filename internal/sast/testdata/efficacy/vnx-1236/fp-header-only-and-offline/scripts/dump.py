import csv

# Offline maintenance script: writes a local file nobody downloads.
with open("dump.csv", "w", newline="") as fh:
    writer = csv.writer(fh)
    writer.writerow(["id", "name"])
    for row in rows():
        writer.writerow(row)
