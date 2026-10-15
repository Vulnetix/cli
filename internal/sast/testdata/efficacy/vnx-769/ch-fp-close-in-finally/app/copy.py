def checksum_all(paths):
    total = 0
    for p in paths:
        f = open(p, "rb")
        try:
            total += sum(f.read())
        finally:
            f.close()
    for p in paths:
        with open(p) as fh:
            total += len(fh.read())
    return total
