import logging
import os
from pathlib import Path


def load():
    with open("/tmp/state.json") as fh:
        return fh.read()


def claim():
    with open("/tmp/app.lock", "x") as fh:
        fh.write(str(os.getpid()))


def peek():
    return Path("/tmp/app.lock").read_text()


def configure():
    logging.FileHandler("/var/log/app/service.log")
    with open("/var/lib/app/state.json", "w") as fh:
        fh.write("{}")
