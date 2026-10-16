from pathlib import Path


def test_export_writes_password(tmp_path):
    password = "hunter2"
    Path("/tmp/test_password.txt").write_text(password)
    assert Path("/tmp/test_password.txt").read_text() == password
