import pickle

from fastapi import FastAPI, Request

app = FastAPI()


@app.post("/jobs")
async def submit(request: Request):
    raw = await request.body()
    job = pickle.loads(
        raw
    )
    return {"queued": job.name}
