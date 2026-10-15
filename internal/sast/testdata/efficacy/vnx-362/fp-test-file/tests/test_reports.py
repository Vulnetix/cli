import os


def test_save(tmp_path):
    p = str(tmp_path / "r.txt")
    if not os.path.exists(p):
        with open(p, "w") as fh:
            fh.write("x")
