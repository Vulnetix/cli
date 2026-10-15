import requests


def fetch(url):
~>    # FIXME: SSL verification disabled until the staging cert is fixed
    return requests.get(url, verify=False)


def store(path, data):
~>    # TODO: certificate verification is turned off, re-enable before release
    return write(path, data)
