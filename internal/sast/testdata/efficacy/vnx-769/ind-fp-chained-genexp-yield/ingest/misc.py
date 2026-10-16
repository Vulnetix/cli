def sizes(paths):
    out = []
    for p in paths:
        out.append(len(open(p).read()))
    return out


def lines(paths):
    return sum(1 for _ in (open(p) for p in paths))


def stream(paths):
    for p in paths:
        fh = open(p)
        yield fh


# for p in paths: fh = open(p)
DOC = "files = [open(p) for p in paths]"
