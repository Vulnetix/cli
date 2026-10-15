def test_export(tmp_path):
    for name in ["a", "b"]:
        open(tmp_path / name, "w").write("x")
    open(tmp_path / "c", "w").write("x")
    open(tmp_path / "d", "w").write("x")
    open(tmp_path / "e", "w").write("x")
    open(tmp_path / "f", "w").write("x")
    open(tmp_path / "g", "w").write("x")
    open(tmp_path / "h", "w").write("x")
    assert open(tmp_path / "a").read() == "x"
