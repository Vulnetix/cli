import json
import pickle

import msgpack


def handle(body, cache, obj):
    data = json.loads(body)
    packed = msgpack.unpackb(body, raw=False)
    blob = pickle.dumps(obj, protocol=pickle.HIGHEST_PROTOCOL)
    cfg = cache.loads(body)
    item = self_loads(body)
    return data, packed, blob, cfg, item
