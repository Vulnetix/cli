from tempfile import TemporaryDirectory, mkstemp


def run():
    fd, path = mkstemp()
    with TemporaryDirectory() as d:
        return d, path
