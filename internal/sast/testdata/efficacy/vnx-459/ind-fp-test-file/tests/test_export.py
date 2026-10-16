import tempfile

from export import write_report


def test_write_report():
    out = tempfile.mkdtemp()
    write_report(out)
