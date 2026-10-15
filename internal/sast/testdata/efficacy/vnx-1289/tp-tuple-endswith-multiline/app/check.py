from werkzeug.utils import secure_filename
from flask import request


def check():
    filename = secure_filename(request.files["upload"].filename)
~>    if filename.endswith((
        ".py", ".sh", ".exe",
    )):
        raise ValueError("executable upload")
    return filename
