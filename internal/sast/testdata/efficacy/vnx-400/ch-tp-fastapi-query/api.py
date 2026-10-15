import asyncio

from fastapi import FastAPI, Query

app = FastAPI()


@app.get("/fib")
def fib(n: int = Query(10)):
    a, b = 0, 1
~>    for _ in range(n):
        a, b = b, a + b
    return {"n": a}


@app.get("/delay")
async def delay(seconds: float = 1.0):
~>    await asyncio.sleep(seconds)
    return {"slept": seconds}
