import json
import tempfile


def load():
    with open("/tmp/state.json") as fh:
        return json.load(fh)


def create_once(data):
    with open("/tmp/state.lock", "x") as fh:
        fh.write(data)


def scratch():
    fd, name = tempfile.mkstemp(dir="/tmp", suffix=".json")
    with open(name, "w") as fh:
        fh.write("{}")
    return name
