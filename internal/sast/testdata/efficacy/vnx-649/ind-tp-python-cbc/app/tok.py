from Crypto.Cipher import AES
import base64
from flask import request

def read_token(key):
    raw = base64.b64decode(request.cookies["tok"])
    cipher = AES.new(key, AES.MODE_CBC, raw[:16])
~>    return cipher.decrypt(raw[16:])
