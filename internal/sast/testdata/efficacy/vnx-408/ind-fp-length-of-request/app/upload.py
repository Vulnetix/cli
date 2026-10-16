from flask import Flask, jsonify, request

app = Flask(__name__)


@app.post("/upload")
def upload():
    files = request.files.getlist("files")
    saved = []
    for i in range(len(files)):
        saved.append(files[i].filename)
    return jsonify(saved=saved)
