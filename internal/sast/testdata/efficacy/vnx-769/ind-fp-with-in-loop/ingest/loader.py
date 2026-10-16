import json


def load_all(paths):
    records = []
    for path in paths:
        with open(path, encoding="utf-8") as fh:
            records.append(json.load(fh))
    return records
