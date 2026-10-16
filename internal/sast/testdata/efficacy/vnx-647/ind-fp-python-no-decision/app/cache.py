from flask import request

@app.after_request
def add_headers(resp):
    if request.path.startswith("/static"):
        resp.headers["Cache-Control"] = "public, max-age=3600"
    if request.path == "/health":
        resp.headers["X-Probe"] = "1"
    return resp
