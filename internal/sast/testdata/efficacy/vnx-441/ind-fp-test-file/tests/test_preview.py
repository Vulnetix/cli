import requests
from flask import Response, request


def fake_preview_handler():
    target = request.args.get("url")
    upstream = requests.get(target, timeout=1)
    return Response(upstream.content)


def test_preview_relays(client, requests_mock):
    requests_mock.get("http://upstream.test/", text="hello")
    rv = client.get("/preview?url=http://upstream.test/")
    assert rv.data == b"hello"
