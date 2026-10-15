from urllib.parse import parse_qsl


def application(environ, start_response):
    length = int(environ.get("CONTENT_LENGTH") or 0)
~>    fields = dict(parse_qsl(environ["wsgi.input"].read(length).decode()))
    start_response("200 OK", [("Content-Type", "text/plain")])
    return [str(len(fields)).encode()]
