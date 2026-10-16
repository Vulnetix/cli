import tempfile


def make_scratch_dir():
    return tempfile.mkdtemp(prefix="scratch-")


def scratch_file(suffix=".bin"):
    handle = tempfile.NamedTemporaryFile(suffix=suffix, delete=False)
    return handle
