from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from service.db import get_db
from service.models import Tenant

router = APIRouter(prefix="/api")


~>@router.delete("/admin/tenants/{tenant_id}")
async def drop_tenant(tenant_id: str, db: Session = Depends(get_db)):
    db.query(Tenant).filter(Tenant.id == tenant_id).delete()
    db.commit()
    return {"status": "dropped"}
