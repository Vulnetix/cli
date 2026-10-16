def test_many(tmp_path):
    for i in range(5):
        fh = open(tmp_path / f"{i}.txt", "w")
        fh.write("x")
