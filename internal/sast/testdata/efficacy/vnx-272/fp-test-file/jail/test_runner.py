import os


def test_enter_jail(tmp_path):
    os.chroot(tmp_path)
    assert os.getcwd() == "/"
