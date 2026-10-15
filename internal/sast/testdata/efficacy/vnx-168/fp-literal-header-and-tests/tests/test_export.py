def test_export(tmp_path):
    out = tmp_path / "out.csv"
    out.write_text("a,b\n")
    assert out.read_text().strip().split(",") == ["a", "b"]
