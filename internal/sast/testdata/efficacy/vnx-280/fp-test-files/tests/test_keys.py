import os


def test_chmod_best_effort(tmp_path):
    p = tmp_path / "key"
    p.write_text("x")
    try:
        os.chmod(p, 0o600)
    except OSError:
        pass
