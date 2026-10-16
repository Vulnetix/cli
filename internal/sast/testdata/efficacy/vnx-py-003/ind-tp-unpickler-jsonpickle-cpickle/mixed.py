import io
import cPickle
import pickle
import jsonpickle


def a(data):
~>    return pickle.Unpickler(io.BytesIO(data)).load()


def b(data):
~>    return cPickle.loads(data)


def c(text):
~>    return jsonpickle.decode(text)
