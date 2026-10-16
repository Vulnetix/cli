from pathlib import Path

BASE = "/data/tenants"


def read(rel):
    full = os.path.abspath(os.path.join(BASE, rel))
    log(rel)
~>    if not full.startswith("/data/tenants"):
        raise ValueError("escape")
    return Path(full).read_text()
