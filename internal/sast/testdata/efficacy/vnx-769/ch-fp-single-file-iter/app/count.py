def count_lines(path):
    lines = [line for line in open(path).readlines()]
    return len(lines)


def names(paths):
    return [p.name for p in paths if p.suffix == ".open("]
