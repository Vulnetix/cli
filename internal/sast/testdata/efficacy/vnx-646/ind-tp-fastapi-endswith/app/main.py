import shutil
import uuid

from fastapi import FastAPI, File, HTTPException, UploadFile

app = FastAPI()


@app.post("/imports")
async def import_sheet(upload: UploadFile = File(...)):
~>    if not upload.filename.lower().endswith((".csv", ".xlsx")):
        raise HTTPException(status_code=415, detail="CSV or XLSX only")
    target = f"/srv/imports/{uuid.uuid4().hex}"
    with open(target, "wb") as out:
        shutil.copyfileobj(upload.file, out)
    return {"id": target}
