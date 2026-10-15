from flask import request

# if f.filename.endswith(".png"): trust it  <- never do this
HELP = "Checking f.filename.endswith('.png') proves nothing about the content."


def upload():
    f = request.files["file"]
    return HELP
