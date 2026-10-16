def first_line(path):
    fh = open(path, encoding="utf-8")
    with fh:
        return fh.readline()
