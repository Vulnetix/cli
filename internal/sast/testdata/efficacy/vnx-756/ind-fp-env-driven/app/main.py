import os

from fastapi import FastAPI

DEBUG = os.environ.get("APP_DEBUG", "") == "1"
app = FastAPI(title="Orders", debug=DEBUG)
other = FastAPI(debug=False)
