import json
import os
from http.server import BaseHTTPRequestHandler, HTTPServer


class Status(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
~>        self.wfile.write(json.dumps(dict(os.environ)).encode())


HTTPServer(("", 8080), Status).serve_forever()
