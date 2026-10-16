def test_leak(tmp_path):
    fh = open(tmp_path / "a.txt", "w")
    fh.write("x")
