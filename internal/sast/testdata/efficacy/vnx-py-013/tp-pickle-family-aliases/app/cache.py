import base64
import pickle
import pickle as pkl

import cloudpickle
import dill
from flask import request


def restore(blob):
~>    return pkl.loads(blob)


def from_cookie():
~>    return pickle.loads(base64.b64decode(request.cookies["session"]))


def load_all(p, payload, fh):
~>    obj = dill.load(open(p, "rb"))
~>    fn = cloudpickle.loads(payload)
~>    data = pickle.Unpickler(fh).load()
    return obj, fn, data
