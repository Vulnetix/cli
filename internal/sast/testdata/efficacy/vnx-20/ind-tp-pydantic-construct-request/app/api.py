from fastapi import FastAPI, Request
from pydantic import BaseModel, Field

app = FastAPI()


class Invoice(BaseModel):
    customer_id: int
    total: float = Field(gt=0)


@app.post("/invoices")
async def create_invoice(request: Request):
    payload = await request.json()
~>    invoice = Invoice.model_construct(**payload)
    return {"customer": invoice.customer_id, "total": invoice.total}
