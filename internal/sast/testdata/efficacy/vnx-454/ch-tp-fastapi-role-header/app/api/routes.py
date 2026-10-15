from fastapi import APIRouter, HTTPException, Request

router = APIRouter()


@router.delete("/projects/{project_id}")
async def delete_project(project_id: int, request: Request):
~>    caller_role = request.headers.get("X-User-Role", "viewer")
    if caller_role != "owner":
        raise HTTPException(status_code=403)
    await projects.delete(project_id)
    return {"deleted": project_id}
