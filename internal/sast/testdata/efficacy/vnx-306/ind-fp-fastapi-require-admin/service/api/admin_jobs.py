from fastapi import APIRouter, Depends

from service.auth import require_admin
from service.jobs import requeue

router = APIRouter()


@router.post("/admin/jobs/{job_id}/requeue")
async def requeue_job(job_id: int, admin=Depends(require_admin)):
    requeue(job_id, actor=admin.email)
    return {"ok": True}


@router.post("/admin/jobs/purge", dependencies=[Depends(require_admin)])
async def purge_jobs():
    return {"purged": True}
