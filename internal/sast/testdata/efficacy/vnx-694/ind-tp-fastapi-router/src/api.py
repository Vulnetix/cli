from fastapi import APIRouter

router = APIRouter()


@router.get("/items/{item_id}")
async def read_item(item_id: int):
    return {"id": item_id}


@router.post("/items")
async def create_item(item: dict):
    return item


~>@router.get("/items/{item_id}")
async def read_item_authorised(item_id: int):
    return {"id": item_id, "owner": True}
