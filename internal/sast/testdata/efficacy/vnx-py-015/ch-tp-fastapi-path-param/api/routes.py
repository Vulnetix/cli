import re

from fastapi import FastAPI

app = FastAPI()
NAMES = ["alpha", "beta", "gamma"]


@app.get("/names/{expr}")
def filter_names(expr: str):
~>    rx = re.compile(expr)
    return [n for n in NAMES if rx.search(n)]
