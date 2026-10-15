import uuid


def store(upload):
    filename = f"{uuid.uuid1()}.png"
    token = uuid.uuid4().hex
    upload.save(filename)
    return filename, token
