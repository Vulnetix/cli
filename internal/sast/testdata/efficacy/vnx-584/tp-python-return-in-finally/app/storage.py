def load(path, cache=None):
    try:
        return parse(path)
    finally:
        if cache is not None:
~>            return cache
        close(path)


def save(path, data):
    try:
        write(path, data)
    finally:
~>        return True
