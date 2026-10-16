import json
from pathlib import Path


def load_handoff():
    with open("/tmp/handoff.json") as fh:
        return json.load(fh)


def load_bytes():
    with open("/var/tmp/handoff.bin", "rb") as fh:
        return fh.read()


def claim():
    with open("/tmp/handoff.claim", "x") as fh:
        fh.write("1")


def save(state):
    with open("/var/lib/app/state.json", "w") as fh:
        json.dump(state, fh)
    Path("/var/lib/app/ready").write_text("1")


def peek():
    return Path("/dev/shm/status").read_text()
