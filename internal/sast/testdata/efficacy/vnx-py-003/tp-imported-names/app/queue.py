from pickle import load, loads as unpickle
from dill import Unpickler


def consume(message, stream):
~>    task = unpickle(message.body)
~>    extra = load(stream)
~>    more = Unpickler(stream).load()
    return task, extra, more
