import tempfile


def export_report(rows):
    with tempfile.TemporaryDirectory() as d:
        with tempfile.NamedTemporaryFile(dir=d) as fh:
            fh.write(b"x")
    with tempfile.NamedTemporaryFile(delete=True) as other:
        other.write(b"y")
