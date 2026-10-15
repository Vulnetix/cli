import tempfile


def render_pdf(html, convert):
~>    tmp = tempfile.NamedTemporaryFile(
        suffix=".html", delete=False
    )
    tmp.write(html.encode())
    tmp.close()
    return convert(tmp.name)
