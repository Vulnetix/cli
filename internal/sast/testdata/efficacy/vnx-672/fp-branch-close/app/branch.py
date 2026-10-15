def handle(fh, broken):
    if broken:
        fh.close()
        raise IOError("broken")
    return fh.read()


def maybe(fh, done):
    if done:
        fh.close()
    else:
        fh.write("more")
