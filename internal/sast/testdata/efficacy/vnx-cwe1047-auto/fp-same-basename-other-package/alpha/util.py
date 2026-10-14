from .core import parse


def normalise(text):
    return parse(text).strip()
