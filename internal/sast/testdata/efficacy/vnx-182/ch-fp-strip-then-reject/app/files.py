from flask import abort


def safe_name(name):
    clean = name.replace("../", "")
    if ".." in clean:
        abort(400)
    return clean
