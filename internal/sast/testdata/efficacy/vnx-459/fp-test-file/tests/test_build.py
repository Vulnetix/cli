import tempfile


def test_build():
    workdir = tempfile.mkdtemp()
    assert workdir
