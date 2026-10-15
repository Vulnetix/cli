import os
import tempfile


def scratch(data):
    with tempfile.NamedTemporaryFile("w", delete=False) as fh:
        fh.write(data)
    fd, name = tempfile.mkstemp(dir="/tmp")
    os.write(fd, data.encode())
    os.close(fd)
    with tempfile.TemporaryDirectory() as d:
        with open(os.path.join(d, "out.txt"), "w") as out:
            out.write(data)
    return name
