import pickle
import redis

client = redis.Redis()


def get_session(session_id):
    raw = client.get("session:" + session_id)
    if raw is None:
        return None
~>    return pickle.loads(raw)


def read_model(path):
    with open(path, "rb") as f:
~>        return pickle.load(f)
