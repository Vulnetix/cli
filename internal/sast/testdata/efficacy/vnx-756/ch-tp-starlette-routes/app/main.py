from starlette.applications import Starlette
from starlette.routing import Route

from app.views import homepage

routes = [Route("/", homepage)]
~>app = Starlette(debug=True, routes=routes)
