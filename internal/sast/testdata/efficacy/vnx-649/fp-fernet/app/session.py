import json

from cryptography.fernet import Fernet
from flask import request

f = Fernet(KEY)


def read():
    return json.loads(f.decrypt(request.cookies["s"].encode()))
