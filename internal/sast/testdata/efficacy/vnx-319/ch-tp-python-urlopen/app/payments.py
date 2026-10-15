import json
import urllib.request


def charge(payload):
    data = json.dumps(payload).encode()
~>    with urllib.request.urlopen("http://payments.acme-corp.com/v1/charge", data) as resp:
        return json.load(resp)
