from starlette.applications import Starlette
from starlette.middleware.sessions import SessionMiddleware

app = Starlette()
app.add_middleware(SessionMiddleware, secret_key=load_secret(), same_site="lax", https_only=True)


def cookie_policy(same_site=None):
    if same_site is None:
        return "lax"
    return same_site
