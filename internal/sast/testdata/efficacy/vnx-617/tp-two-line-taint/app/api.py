from fastapi import Request


async def upload(request: Request):
    size = int(request.headers.get("content-length", "0"))
~>    assert size < 10_000_000
    name = request.query_params.get("name")
~>    assert name and "/" not in name
    return await store(name, request)
