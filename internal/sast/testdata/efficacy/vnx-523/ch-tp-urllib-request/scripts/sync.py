import urllib.request


def push(api_key, payload):
~>    req = urllib.request.Request("http://ingest.metrics-vendor.com/v1/push", data=payload, headers={"X-Api-Key": api_key})
    return urllib.request.urlopen(req)
