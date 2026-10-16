import copy
import json
import pickle
import msgpack


def save(obj, path):
    with open(path, "wb") as f:
        pickle.dump(obj, f)
    return pickle.dumps(obj)


def clone(obj):
    return pickle.loads(pickle.dumps(obj))


def parse(text, raw):
    return json.loads(text), msgpack.unpackb(raw)
