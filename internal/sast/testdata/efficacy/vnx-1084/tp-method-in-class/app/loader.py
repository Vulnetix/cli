class Loader:
    def __init__(self, root):
        self.root = root

~>    def load(self):
        a = open(self.root + "/a.csv").read()
        b = open(self.root + "/b.csv").read()
        c = open(self.root + "/c.csv").read()
        d = open(self.root + "/d.csv").read()

        e = open(self.root + "/e.csv").read()
        # keep the legacy file too
        f = open(self.root + "/f.csv").read()
        g = open(self.root + "/g.csv").read()
        h = open(self.root + "/h.csv").read()
        return [a, b, c, d, e, f, g, h]

    def size(self):
        return len(self.load())
