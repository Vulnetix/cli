def read_all(paths):
    out = []
    for p in paths:
        with open(p) as fh:
~>        	out.append(fh.read())
    return out
