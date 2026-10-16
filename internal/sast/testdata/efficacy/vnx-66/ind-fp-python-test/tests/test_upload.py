import io
import os

from werkzeug.datastructures import FileStorage


def test_save_keeps_name(tmp_path):
    f = FileStorage(stream=io.BytesIO(b"x"), filename="report.pdf")
    f.save(os.path.join(tmp_path, f.filename))
    assert (tmp_path / "report.pdf").exists()
