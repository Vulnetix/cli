import copy
import pickle


def clone(obj):
    return pickle.loads(pickle.dumps(obj, protocol=pickle.HIGHEST_PROTOCOL))


def check_picklable(session):
    restored = pickle.loads(pickle.dumps(session))
    return restored == session
