import pickle

# pickle.loads(untrusted) would run code; we only round-trip our own objects
HELP = "never call pickle.loads(data) on uploads"


def deep_copy(obj):
    return pickle.loads(pickle.dumps(obj, protocol=pickle.HIGHEST_PROTOCOL))


def save(obj, fh):
    pickle.dump(obj, fh)
    return pickle.dumps(obj)


def other(serializer, mypickle, blob):
    x = serializer.loads(blob)
    y = mypickle.loads(blob)
    return x, y
