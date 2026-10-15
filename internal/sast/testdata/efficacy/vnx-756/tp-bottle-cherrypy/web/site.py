import bottle
from bottle import route, run, debug
import cherrypy


@route("/")
def index():
    return "hi"


~>bottle.debug(True)
~>debug(True)
~>run(host="0.0.0.0", port=8080, debug=True)

cherrypy.config.update({
    "server.socket_host": "0.0.0.0",
~>    "request.show_tracebacks": True,
})
