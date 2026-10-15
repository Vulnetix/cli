import os

from fastapi import UploadFile, HTTPException


async def upload(file: UploadFile):
    _, ext = os.path.splitext(file.filename)
~>    if ext.lower() not in {".csv", ".xlsx"}:
        raise HTTPException(400, "unsupported")
    return await import_sheet(file)
