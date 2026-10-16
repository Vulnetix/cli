from starlette.requests import Request
from starlette.responses import JSONResponse


async def export_audit_log(request: Request):
    mode = request.query_params.get("mode", "basic")
~>    is_admin = mode == "superuser"
    if is_admin:
        return JSONResponse({"entries": await load_all_entries()})
    return JSONResponse({"entries": []}, status_code=403)
