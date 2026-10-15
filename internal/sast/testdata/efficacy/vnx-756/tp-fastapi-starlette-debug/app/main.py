from fastapi import FastAPI
from starlette.applications import Starlette
from starlette.routing import Route

~>api = FastAPI(debug=True)

~>app = FastAPI(
    title="Orders",
    version="1.2.0",
    debug=True,
)

routes = [Route("/", lambda request: None)]
~>admin = Starlette(debug = True, routes=routes)
