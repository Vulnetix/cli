import requests


def fetch(url):
    """Do not pass verify=False to requests.get(url, verify=False) in production."""
    # requests.get(url, verify=False)  # removed, see ticket 4411
    return requests.get(url, timeout=3)
