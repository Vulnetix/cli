from urllib.request import urlopen

from fastapi import FastAPI, Request
from fastapi.responses import PlainTextResponse

api = FastAPI()


@api.get("/mirror")
async def mirror(request: Request):
~>    return PlainTextResponse(urlopen(request.query_params["u"]).read())
