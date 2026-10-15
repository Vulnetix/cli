import os


def test_world_writable_detected(tmp_path):
    p = tmp_path / "f"
    p.write_text("x")
    os.chmod(p, 0o777)
    os.umask(0)
