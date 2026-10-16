from fastapi import FastAPI

# FastAPI(debug=True) shows tracebacks; never do this in prod
HELP = "set debug=True only locally: cherrypy.config.update({'request.show_tracebacks': True})"
app = FastAPI(title="Safe")
