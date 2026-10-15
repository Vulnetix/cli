import tempfile


def make_scratch_dir():
    path = tempfile.mkdtemp()
    return path


def make_scratch_file():
    return tempfile.mkstemp()
