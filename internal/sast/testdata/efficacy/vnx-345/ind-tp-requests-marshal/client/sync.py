import marshal

import requests


def fetch_compiled(module):
    resp = requests.get(f"https://cache.example.com/modules/{module}.bin", timeout=30)
    blob = resp.content
~>    return marshal.loads(blob)
