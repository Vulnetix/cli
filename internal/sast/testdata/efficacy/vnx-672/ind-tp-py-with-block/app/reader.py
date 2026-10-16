def load(path):
    with open(path) as cfg:
        first = cfg.readline()
~>    rest = cfg.read()
    return first, rest
