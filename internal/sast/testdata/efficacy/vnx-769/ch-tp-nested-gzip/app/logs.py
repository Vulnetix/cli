import gzip


def load_all(roots):
    data = []
    for root in roots:
        for p in root.iterdir():
~>            g = gzip.open(p, "rt")
            data.append(g.read())
    return data
