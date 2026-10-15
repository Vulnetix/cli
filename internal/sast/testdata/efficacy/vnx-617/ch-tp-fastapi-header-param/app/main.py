from fastapi import FastAPI, Header

from app.config import settings

app = FastAPI()


@app.post("/admin/reindex")
def reindex(
    x_admin_token: str = Header(...),
):
~>    assert x_admin_token == settings.ADMIN_TOKEN, "bad token"
    return {"queued": True}
