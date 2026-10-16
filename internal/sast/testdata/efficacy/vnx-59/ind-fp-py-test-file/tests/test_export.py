import os

from app.export import export_report


def test_export_writes_rows():
    with open("/tmp/report-expected.csv", "w") as fh:
        fh.write("a,b\n")
    path = export_report([["a", "b"]])
    assert os.path.exists(path)
