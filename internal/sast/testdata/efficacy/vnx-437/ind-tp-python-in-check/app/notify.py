import httpx
from fastapi import HTTPException


async def send_callback(callback: str, payload: dict) -> None:
    if "trusted-partner.com" not in callback:
        raise HTTPException(status_code=400, detail="callback host not allowed")
    async with httpx.AsyncClient(timeout=10) as client:
~>        await client.post(callback, json=payload)
