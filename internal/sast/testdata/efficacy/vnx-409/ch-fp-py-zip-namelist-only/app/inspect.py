import zipfile

from flask import Flask, request

app = Flask(__name__)


@app.post("/inspect")
def inspect_upload():
    with zipfile.ZipFile(request.files["f"]) as zf:
        return {"names": zf.namelist()}
