from fastapi import FastAPI
from starlette.middleware.sessions import SessionMiddleware

app = FastAPI()
~>app.add_middleware(SessionMiddleware, secret_key="x" * 32, same_site="none")
