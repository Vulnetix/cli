import base64


def load(cfg):
    db_password = base64.b64decode(cfg["db_password"]).decode()
    avatar = base64.b64encode(cfg["avatar_bytes"])
    return db_password, avatar
