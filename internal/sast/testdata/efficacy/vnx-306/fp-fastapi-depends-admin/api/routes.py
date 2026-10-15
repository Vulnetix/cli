from fastapi import APIRouter, Depends

from .security import require_admin

router = APIRouter()


@router.delete("/api/admin/tenants/{tenant_id}")
async def drop_tenant(tenant_id: str, admin=Depends(require_admin)):
    return {"deleted": tenant_id}


@router.post("/admin/rebuild", dependencies=[Depends(require_admin)])
async def rebuild():
    return {"ok": True}
