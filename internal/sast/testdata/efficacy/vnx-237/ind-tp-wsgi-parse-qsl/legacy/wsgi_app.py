from urllib.parse import parse_qsl


def application(environ, start_response):
    length = int(environ.get("CONTENT_LENGTH") or 0)
    raw = environ["wsgi.input"].read(length)
~>    pairs = parse_qsl(raw.decode("utf-8"))
    start_response("200 OK", [("Content-Type", "text/plain")])
    return [str(len(pairs)).encode()]
