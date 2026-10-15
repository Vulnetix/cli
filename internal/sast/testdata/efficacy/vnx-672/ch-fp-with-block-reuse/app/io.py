def load(path):
    with open(path) as fh:
        data = fh.read()
    with open(path + ".bak", "w") as fh:
        fh.write(data)
    return data


def closer(f):
    f.close()
    if f.closed:
        log("closed")
    "f.close(); f.read()"
