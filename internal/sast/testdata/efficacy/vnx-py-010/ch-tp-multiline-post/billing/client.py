import requests


def charge(api, payload):
    resp = requests.post(
        f"{api}/charges",
        json=payload,
        timeout=10,
~>        verify = False,
    )
    resp.raise_for_status()
    return resp.json()


def ping(url):
~>    return requests.request("GET", url, verify=False).status_code
