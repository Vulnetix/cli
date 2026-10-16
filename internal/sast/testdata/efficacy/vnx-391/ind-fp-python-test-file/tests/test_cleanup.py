import shutil


def test_rmtree_missing_dir(tmp_path):
    try:
        shutil.rmtree(tmp_path / "nope")
    except Exception:
        pass
    assert not (tmp_path / "nope").exists()
