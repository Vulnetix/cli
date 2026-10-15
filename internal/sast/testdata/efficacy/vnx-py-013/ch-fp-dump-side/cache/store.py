import pickle

import joblib


def save(obj, path):
    with open(path, "wb") as fh:
        pickle.dump(obj, fh, protocol=pickle.HIGHEST_PROTOCOL)


def blob(obj):
    return pickle.dumps(obj)


def save_model(model, path):
    joblib.dump(model, path)
