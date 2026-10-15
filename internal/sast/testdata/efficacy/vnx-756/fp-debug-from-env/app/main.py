import os
from fastapi import FastAPI
import tornado.web
from tornado.options import define, options

DEBUG = os.environ.get("APP_DEBUG") == "1"
define("debug", default=True, help="debug mode")

api = FastAPI(debug=DEBUG)
other = FastAPI(debug=os.getenv("DEBUG", "") == "true")
tapp = tornado.web.Application([], debug=options.debug)
