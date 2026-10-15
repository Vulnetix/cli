import pickle


def load_cache(path):
    with open(path, "rb") as fh:
        return pickle.load(fh)


def roundtrip(obj):
    return pickle.loads(pickle.dumps(obj))
