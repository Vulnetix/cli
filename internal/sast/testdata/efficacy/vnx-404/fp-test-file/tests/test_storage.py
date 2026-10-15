def test_load(tmp_path):
    fh = open(tmp_path / "x.json", "w")
    fh.write("{}")
