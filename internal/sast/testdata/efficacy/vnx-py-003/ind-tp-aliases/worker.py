import pickle as pkl
from pickle import loads as unpickle
import dill
import cloudpickle


def handle(message, blob, path):
~>    a = pkl.loads(blob)
~>    task = unpickle(message.body)
~>    b = dill.loads(blob)
    with open(path, "rb") as fh:
~>        c = cloudpickle.load(fh)
    return a, task, b, c
