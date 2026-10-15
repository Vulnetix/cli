import requests


def fetch(url, token):
    headers = dict()
    resp = requests.get(
        url,
        headers={
            'Accept': 'application/json',
            'Authorization': 'Bearer ' + token,
~>            'Accept': 'text/html',
        },
    )
    return resp
