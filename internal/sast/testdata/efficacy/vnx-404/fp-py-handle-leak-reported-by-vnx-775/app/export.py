import csv
import codecs


def export(rows, dest):
    target = open(dest, 'w', newline='')
    writer = csv.writer(target)
    for row in rows:
        writer.writerow(row)
    return len(rows)


def read_legacy(path):
    src = codecs.open(
        path, encoding="latin-1")
    return src.read().splitlines()
