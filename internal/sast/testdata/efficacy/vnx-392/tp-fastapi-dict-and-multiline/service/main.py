from fastapi import FastAPI

app = FastAPI()


@app.get("/items/{item_id}")
def read_item(item_id: int):
    try:
        return repo.get(item_id)
    except KeyError:
~>        return {"error": "item not found"}


@app.post("/items")
def add_item(item: Item):
    try:
        repo.add(item)
    except Exception as exc:
~>        return JSONResponse(
            content={"detail": f"could not save: {exc}"},
        )
    return {"ok": True}
