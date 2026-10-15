from urllib.parse import parse_qs, parse_qsl


def application(environ, start_response):
    size = int(environ.get("CONTENT_LENGTH") or 0)
    body = environ["wsgi.input"].read(size).decode()
~>    form = parse_qs(body)
    start_response("200 OK", [])
    return [form.get("q", [""])[0].encode()]


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
~>        pairs = parse_qsl(self.rfile.read(int(self.headers["Content-Length"])).decode())
        self.reply(pairs)
