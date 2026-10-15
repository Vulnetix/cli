from fastapi import FastAPI

app = FastAPI()


@app.post("/tokens/refresh-cache")
async def refresh_cache():
    return {}


@app.post("/orders")
async def orders(order: dict):
    return order

# @app.post("/login")  -- removed, handled by the identity provider
