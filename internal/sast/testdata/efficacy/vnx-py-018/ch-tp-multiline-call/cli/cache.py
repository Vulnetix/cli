import tempfile as tmp


def scratch_path():
~>    return tmp.mktemp(
        suffix=".cache",
    )
