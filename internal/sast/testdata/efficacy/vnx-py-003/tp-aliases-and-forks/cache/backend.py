import _pickle
import cloudpickle
import dill
import pickle as pkl

import cPickle


def get(redis_client, key):
    blob = redis_client.get(key)
~>    a = pkl.loads(blob)
~>    b = cPickle.loads(blob)
~>    c = dill.loads(blob)
~>    d = cloudpickle.loads(blob)
~>    e = _pickle.loads(blob)
    return a, b, c, d, e
