import os

from starlette.applications import Starlette
from starlette.config import Config

config = Config(".env")
DEBUG = config("DEBUG", cast=bool, default=False)
app = Starlette(debug=DEBUG, routes=[])
other = Starlette(debug=os.getenv("DEBUG") == "1")
