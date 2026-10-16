import json


def load_settings(path):
    fh = open(path, "rb")
    raw = fh.read()
    return json.loads(raw)
