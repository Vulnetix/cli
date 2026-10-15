from yaml import SafeLoader, load


def read(fh):
    return load(fh, Loader=SafeLoader)
