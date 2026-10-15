from fastapi import APIRouter, Depends

from .db import get_db

router = APIRouter()


~>@router.delete("/api/admin/tenants/{tenant_id}")
async def drop_tenant(tenant_id: str, db=Depends(get_db)):
    await db.tenants.delete(tenant_id)
    return {"deleted": tenant_id}
