import os

from fastapi import FastAPI

DEBUG = os.environ.get("APP_DEBUG") == "1"
app = FastAPI(debug=DEBUG, title="orders")
other = FastAPI(debug=False)
