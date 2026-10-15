import os

import requests


def sync():
    url = os.environ["SYNC_URL"]
    return requests.get(url, timeout=10)
