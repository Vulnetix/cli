import requests


def push(base, api_key, payload):
~>    return requests.post(f"{base}/v1/report", params={"api_key": api_key}, json=payload, timeout=10)
