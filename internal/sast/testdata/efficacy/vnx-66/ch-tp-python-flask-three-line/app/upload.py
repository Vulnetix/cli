import os
from flask import Flask, request

app = Flask(__name__)
app.config["UPLOAD_FOLDER"] = "C:\\inetpub\\uploads"


@app.post("/docs")
def upload_doc():
    f = request.files["doc"]
~>    dest = os.path.join(app.config["UPLOAD_FOLDER"], f.filename)
    f.save(dest)
    return "ok"


@app.post("/avatar")
def upload_avatar():
    file = request.files.get("avatar")
~>    file.save(os.path.join(app.config["UPLOAD_FOLDER"], os.path.basename(file.filename)))
    return "ok"
