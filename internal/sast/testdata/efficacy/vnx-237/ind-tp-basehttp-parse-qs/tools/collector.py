import urllib.parse
from http.server import BaseHTTPRequestHandler


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        data = self.rfile.read(n).decode()
~>        fields = urllib.parse.parse_qs(data)
        self.send_response(204)
        self.end_headers()
        record(fields)
