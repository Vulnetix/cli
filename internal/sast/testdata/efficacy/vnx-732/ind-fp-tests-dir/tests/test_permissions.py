import os
import stat


def test_world_writable_file_is_detected(tmp_path):
    p = tmp_path / "loose.txt"
    p.write_text("x")
    os.chmod(p, 0o777)
    assert os.stat(p).st_mode & stat.S_IWOTH
