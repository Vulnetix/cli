import pickle

import requests

MODEL_URL = "https://models.example.com/classifier.pkl"


def fetch_model():
    resp = requests.get(MODEL_URL, timeout=30)
    resp.raise_for_status()
    return pickle.loads(resp.content)
