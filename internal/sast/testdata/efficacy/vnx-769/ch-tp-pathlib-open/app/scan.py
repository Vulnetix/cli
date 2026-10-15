from pathlib import Path


def headers(root: Path):
    out = []
    for path in root.glob("*.log"):
~>        fh = path.open("rb")
        out.append(fh.readline())
    return out
