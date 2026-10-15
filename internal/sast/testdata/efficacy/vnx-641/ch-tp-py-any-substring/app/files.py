ALLOWED = [".png", ".jpg", ".gif"]


def accept(upload):
    filename = upload.filename
~>    if not any(ext in filename for ext in ALLOWED):
        raise ValueError("bad type")
~>    if ".php" in filename:
        raise ValueError("no scripts")
