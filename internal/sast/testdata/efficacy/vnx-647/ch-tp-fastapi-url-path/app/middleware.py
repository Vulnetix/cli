from fastapi import FastAPI, HTTPException, Request

app = FastAPI()


@app.middleware("http")
async def admin_only(request: Request, call_next):
~>    if request.url.path.startswith("/admin"):
        if not request.headers.get("x-admin"):
            raise HTTPException(status_code=403)
    return await call_next(request)
