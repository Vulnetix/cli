import os
from pathlib import Path

from aiohttp import web
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

api = FastAPI()
~>api.mount("/", StaticFiles(directory="."), name="root")
here = Path(__file__).resolve().parent
~>api.mount("/code", StaticFiles(directory=here), name="code")

app = web.Application()
~>app.router.add_static("/", os.path.dirname(__file__))
