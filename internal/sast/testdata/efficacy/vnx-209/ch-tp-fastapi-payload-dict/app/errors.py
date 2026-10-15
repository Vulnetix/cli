import traceback

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

app = FastAPI()


@app.exception_handler(Exception)
async def unhandled(request: Request, exc: Exception):
    payload = {"error": str(exc), "trace": traceback.format_exc()}
~>    return JSONResponse(status_code=500, content=payload)
