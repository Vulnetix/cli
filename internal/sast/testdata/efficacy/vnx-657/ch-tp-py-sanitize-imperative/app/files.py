import os


def save_upload(name, body):
~>    # TODO(alice): sanitize filename before writing
    with open(os.path.join("/srv/uploads", name), "wb") as fh:
        fh.write(body)
