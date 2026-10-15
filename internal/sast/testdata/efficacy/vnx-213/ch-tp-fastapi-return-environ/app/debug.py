import os

from fastapi import APIRouter

router = APIRouter()


@router.get("/debug/env")
def env_dump():
~>    return dict(os.environ)


@router.get("/debug/info")
async def info():
~>    return {"status": "ok", "environment": os.environ.copy()}
