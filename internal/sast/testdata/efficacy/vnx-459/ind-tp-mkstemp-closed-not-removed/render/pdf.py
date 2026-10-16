import os
import tempfile

from weasyprint import HTML


def render_invoice(html, mailer, recipient):
~>    fd, path = tempfile.mkstemp(suffix=".pdf")
    os.close(fd)
    HTML(string=html).write_pdf(path)
    mailer.send(recipient, attachment=path)
