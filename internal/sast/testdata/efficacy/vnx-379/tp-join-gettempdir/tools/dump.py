import os
import tempfile


def dump(blob):
~>    path = os.path.join(tempfile.gettempdir(), "dump.bin")
    with open(path, "wb") as f:
        f.write(blob)
