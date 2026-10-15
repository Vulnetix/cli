import os

from starlette.applications import Starlette
from starlette.middleware.sessions import SessionMiddleware

app = Starlette()
~>app.add_middleware(SessionMiddleware, secret_key=os.environ["SECRET"], same_site="none", https_only=True)

SESSION_COOKIE_SECURE = True
~>CSRF_COOKIE_SAMESITE = False
