import os
from pathlib import Path

HERE = Path(__file__).parent


def write_outputs(data, src):
    (Path(__file__).parent / "out.json").write_text(data)
    Path(__file__).with_suffix(".bak").write_text(src)
    with open(os.path.join(os.path.dirname(__file__), "out.txt"), "w") as fh:
        fh.write(data)
    with open(os.path.abspath(__file__)) as fh:
        return fh.read()
