import os


def test_umask_cleared():
    os.umask(0)
    assert os.umask(0o022) == 0
