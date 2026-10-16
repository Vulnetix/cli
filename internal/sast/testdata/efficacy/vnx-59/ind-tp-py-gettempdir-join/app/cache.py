import os
import pickle
import tempfile


def save_cache(index):
    path = os.path.join(tempfile.gettempdir(), "search-index.db")
~>    with open(path, "wb") as fh:
        pickle.dump(index, fh)
    return path
