import json


def load(path, strict):
    if strict:
        data = json.load(open(path))
    else:
        data = {}
    try:
        value = int(data["v"])
    except (KeyError, ValueError):
        value = -1
    return data, value


def scan(entries):
    for entry in entries:
        found = entry.match()
        if not found:
            continue
        found = entry.refine()
        print(found)
