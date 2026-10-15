import asyncio

from fastapi import FastAPI, Query

app = FastAPI()


@app.get("/fib")
def fib(n: int = Query(10, ge=1, le=90)):
    a, b = 0, 1
    for _ in range(n):
        a, b = b, a + b
    return {"n": a}


@app.get("/page")
def page(size: int = Query(20, lt=200)):
    return {"items": [None] * size}


def helper(n: int = 3):
    return list(range(n))
