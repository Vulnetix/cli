from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse

app = FastAPI()


@app.get("/out")
async def outbound(request: Request):
~>    return RedirectResponse(request.query_params["to"], status_code=302)
