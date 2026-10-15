import os
import tempfile


def render_pdf(html, convert):
    tmp = tempfile.NamedTemporaryFile(suffix=".html", delete=False)
    try:
        tmp.write(html.encode())
        tmp.close()
        return convert(tmp.name)
    finally:
        os.unlink(tmp.name)


def export(rows):
    fd, path = tempfile.mkstemp()
    os.close(fd)
    try:
        write_rows(path, rows)
    finally:
        os.remove(path)
