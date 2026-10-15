import requests


def test_proxy(client, request):
    target = request.param
    r = requests.get(target)
    return r.text
