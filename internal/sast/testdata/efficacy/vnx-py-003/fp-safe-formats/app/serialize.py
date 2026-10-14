import json
from json import loads

import jsonpickle
import msgpack


def parse(body):
    a = json.loads(body)
    b = loads(body)
    c = msgpack.unpackb(body, raw=False)
    d = jsonpickle.decode(body, safe=True)
    return a, b, c, d
