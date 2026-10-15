from flask import request


@app.post("/avatar")
def avatar():
    file = request.files["avatar"]
~>    ext = file.filename.split(".")[1].lower()
    if ext not in {"png", "jpg"}:
        abort(400)
    file.save(os.path.join(UPLOADS, file.filename))
