from fastapi import APIRouter, Depends

from .security import require_admin

router = APIRouter()


@router.post("/admin/reindex", dependencies=[Depends(require_admin)])
async def reindex():
    return {"started": True}


@router.delete("/admin/cache")
async def clear_cache(key: str, user=Depends(require_admin)):
    return {"cleared": key}
