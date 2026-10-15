import csv


class Exporter:
    def __init__(self, path):
        self.path = path

    def write(self, rows):
~>        out = open(self.path, "w", newline="")
        writer = csv.writer(out)
        writer.writerows(rows)
        return len(rows)
