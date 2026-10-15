class Reader:
    def __init__(self, path):
        self.fh = open(path)

    def close(self):
        self.fh.close()

    def read(self):
        return self.fh.read()


def done(fh):
    fh.close()
    return


def other(fh, g):
    fh.close()
    g.write("x")
