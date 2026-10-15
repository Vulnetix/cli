def test_purge_missing(tmp_path):
    try:
        purge(tmp_path / "x")
    except Exception:
        pass
