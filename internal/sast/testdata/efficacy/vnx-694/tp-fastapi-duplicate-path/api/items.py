from fastapi import FastAPI, Depends

app = FastAPI()


@app.get("/items/{item_id}")
async def read_item(item_id: int):
    return {"id": item_id}


~>@app.get("/items/{item_id}")
async def read_item_authorized(item_id: int, user=Depends(current_user)):
    return {"id": item_id, "owner": user.id}
