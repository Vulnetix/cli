import json
import os
from flask import request

CONFIG = json.loads(open("config.json").read())
LIMIT = int(os.environ.get("LIMIT", "10"))


def listing():
    size = request.args.get("size", 20, type=int)
    sample = json.loads('{"a": 1}')
    # json.loads(request.data) would be wrong here
    return size, sample, LIMIT
