from app.report import write_report


def test_write_report(tmp_path):
    out = tmp_path / "report.csv"
    write_report(out, [("alice", 3), ("bob", 5)])
    lines = out.read_text().splitlines()
    assert lines[1].split(",") == ["alice", "3"]
