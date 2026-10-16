import os


def test_many(tmp_path):
    open(tmp_path / "1", "w").close()
    open(tmp_path / "2", "w").close()
    open(tmp_path / "3", "w").close()
    open(tmp_path / "4", "w").close()
    open(tmp_path / "5", "w").close()
    open(tmp_path / "6", "w").close()
    open(tmp_path / "7", "w").close()
    open(tmp_path / "8", "w").close()
    os.remove(tmp_path / "1")
