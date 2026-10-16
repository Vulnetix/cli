import gzip


def collect(names):
    handles = []
    for n in names:
~>        handles.append(gzip.open(n))
    return handles
