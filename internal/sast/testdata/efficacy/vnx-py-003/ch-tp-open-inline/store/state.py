import pickle
import pathlib


def restore(path):
~>    return pickle.load(open(path, "rb"))


def restore2(p: pathlib.Path):
    with p.open("rb") as fh:
~>        state = pickle.Unpickler(fh).load()
    return state
