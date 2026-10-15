from flask import Flask, request

app = Flask(__name__)


@app.before_request
def quiet_probes():
    if request.path == "/healthz":
        return "ok", 200
    app.logger.debug("handling %s", request.path)
