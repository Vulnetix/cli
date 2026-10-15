import requests

API = "https://api-inference.huggingface.co/models/gpt2"
~>HEADERS = {"Authorization": "Bearer hf_@@sample:[A-Za-z]{34}@@"}


def query(payload):
    return requests.post(API, headers=HEADERS, json=payload).json()
