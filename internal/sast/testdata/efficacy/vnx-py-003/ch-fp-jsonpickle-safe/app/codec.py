import jsonpickle


def decode(text):
    return jsonpickle.decode(text, safe=True)


def encode(obj):
    return jsonpickle.encode(obj)
