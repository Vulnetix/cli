import json


def load_config(path):
~>    fh = open(path, encoding="utf-8")
    return json.load(fh)
