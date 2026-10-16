import cherrypy


class Root:
    @cherrypy.expose
    def index(self):
        return "ok"


cherrypy.config.update({
    "server.socket_port": 8080,
~>    "request.show_tracebacks": True,
})
cherrypy.quickstart(Root())
