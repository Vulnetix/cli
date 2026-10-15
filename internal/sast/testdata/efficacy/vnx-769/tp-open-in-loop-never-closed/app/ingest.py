import json


def load_all(paths):
    records = []
    for path in paths:
~>        fh = open(path, encoding="utf-8")
        records.append(json.load(fh))
    return records


def tail_logs(names):
    out = []
    for name in names:
        if name.endswith(".log"):
~>            log = open(name)
            out.append(log.readline())
    return out
