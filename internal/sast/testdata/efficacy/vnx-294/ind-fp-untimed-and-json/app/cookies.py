import json
import pickle

from itsdangerous import URLSafeSerializer


def read_prefs(raw, secret):
    s = URLSafeSerializer(secret, salt="prefs")
    return s.loads(raw)


def read_payload(body):
    return json.loads(body)


def read_cache(blob):
    return pickle.loads(blob)
