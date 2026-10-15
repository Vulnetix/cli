from pickle import loads as unpickle


def get(client, key):
    blob = client.get(key)
    if blob is None:
        return None
~>    return unpickle(blob)
