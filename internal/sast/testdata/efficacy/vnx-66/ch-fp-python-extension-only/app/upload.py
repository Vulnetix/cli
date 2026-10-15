import os
import uuid
from flask import Flask, request

app = Flask(__name__)
UPLOADS = "/srv/uploads"


@app.post("/photo")
def photo():
    f = request.files["photo"]
    ext = os.path.splitext(f.filename)[1].lower()
    f.save(os.path.join(UPLOADS, f"{uuid.uuid4().hex}{ext}"))
    return {"original": f.filename}
