from fastapi import FastAPI, Request
from pydantic import BaseModel

app = FastAPI()


class Transfer(BaseModel):
    account: str
    amount: int


@app.post("/transfer")
async def transfer(request: Request):
    payload = await request.json()
~>    t = Transfer.model_construct(**payload)
    return {"queued": t.amount}
