import base64
import json

from Crypto.Cipher import AES
from flask import request

KEY = load_key()


def read_session():
    blob = base64.b64decode(request.cookies["s"])
    cipher = AES.new(KEY, AES.MODE_CBC, blob[:16])
~>    plain = cipher.decrypt(blob[16:])
    return json.loads(unpad(plain))
