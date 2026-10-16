import json


def load_config(path):
    with open(path, encoding="utf-8") as cfg:
        header = cfg.readline()
~>    body = cfg.read()
    return header.strip(), json.loads(body)
