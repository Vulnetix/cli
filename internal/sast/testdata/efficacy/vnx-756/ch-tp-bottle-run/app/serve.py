import bottle
from bottle import route, run


@route("/")
def index():
    return "ok"


~>run(host="0.0.0.0", port=8080, debug=True)
