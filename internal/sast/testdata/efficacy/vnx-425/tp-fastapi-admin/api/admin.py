from fastapi import APIRouter

router = APIRouter(prefix="/api")


~>@router.post("/admin/reindex")
async def reindex():
    return {"started": True}


~>@router.delete("/superuser/cache")
async def clear_cache(key: str):
    return {"cleared": key}
