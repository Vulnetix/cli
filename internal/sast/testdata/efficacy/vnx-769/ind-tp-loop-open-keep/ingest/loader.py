import json


def load_all(paths):
    records = []
    for path in paths:
~>        fh = open(path, encoding="utf-8")
        records.append(json.load(fh))
    return records
