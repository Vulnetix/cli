import json
import os

PORT = int(os.environ.get("PORT", "8080"))
WORKERS = int("4")


def load_settings(path):
    with open(path) as fh:
        return json.loads(fh.read())


def count(rows):
    return int(len(rows) / 2)
