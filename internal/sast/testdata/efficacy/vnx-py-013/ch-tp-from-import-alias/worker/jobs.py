from pickle import loads as unpickle
from joblib import load as load_estimator
import _pickle
import pickle


def handle(message):
    job = unpickle(message.body)
    return job.run()


def handle_fast(blob):
    return _pickle.loads(blob)


def restore(fh):
    return pickle.Unpickler(fh).load()


def estimator(path):
~>    return load_estimator(path)
