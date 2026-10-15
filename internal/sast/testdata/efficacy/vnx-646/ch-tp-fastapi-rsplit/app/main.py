from fastapi import FastAPI, File, HTTPException, UploadFile

app = FastAPI()


@app.post("/images")
async def upload_image(file: UploadFile = File(...)):
~>    if file.filename.rsplit(".", 1)[-1].lower() not in {"png", "jpg", "gif"}:
        raise HTTPException(status_code=415)
    data = await file.read()
    return {"size": len(data)}
