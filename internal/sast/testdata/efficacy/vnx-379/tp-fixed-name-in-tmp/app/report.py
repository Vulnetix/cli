import json
from pathlib import Path


def save(report):
~>    with open("/tmp/report.json", "w") as fh:
        json.dump(report, fh)


def save_user(user, data):
~>    with open(f"/tmp/{user}-export.csv", mode="a") as out:
        out.write(data)


def cache_token(tok):
    target = "/var/tmp/token.cache"
~>    fh = open(target, "wb")
    fh.write(tok)
    fh.close()
~>    Path("/dev/shm/session.lock").write_text("1")
