import json
import os


def load_config(path):
    with open(path) as fh:
        return json.load(fh)


~>def loadConfig(path):
    data = json.loads(open(path).read())
    data.setdefault("debug", os.environ.get("DEBUG") == "1")
    return data
