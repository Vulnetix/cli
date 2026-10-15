def sizes(paths):
    result = []
    for p in paths:
        result.append(len(open(p).read()))
    return result


def first_line(path):
    fh = open(path)
    line = fh.readline()
    fh.close()
    return line


def readers(paths):
    for p in paths:
        fh = open(p)
        yield fh
