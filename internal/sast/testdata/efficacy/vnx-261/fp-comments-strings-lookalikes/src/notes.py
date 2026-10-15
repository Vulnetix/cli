# base64.b64encode(password) only hides it from casual view
import base64


def encode_title(title):
    return base64.b64encode(title.encode())
