from yaml import Loader, load


def read(path):
    with open(path) as fh:
~>        return load(fh, Loader=Loader)
