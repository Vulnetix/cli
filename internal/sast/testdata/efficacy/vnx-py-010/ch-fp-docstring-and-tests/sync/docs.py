import requests


def fetch(url):
    """Fetch url.

    Do not call requests.get(url, verify=False); configure CA_BUNDLE instead.
    """
    # requests.get(url, verify=False) is forbidden here
    return requests.get(url)
