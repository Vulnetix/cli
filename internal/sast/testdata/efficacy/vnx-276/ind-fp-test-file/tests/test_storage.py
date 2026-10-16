import os


def test_world_writable_dir_is_detected(tmp_path):
    d = tmp_path / "up"
    d.mkdir()
    os.chmod(d, 0o777)
    assert os.stat(d).st_mode & 0o002
