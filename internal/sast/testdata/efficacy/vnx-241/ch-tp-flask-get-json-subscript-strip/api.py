from flask import Flask, request

app = Flask(__name__)


@app.post("/tags")
def add_tag():
~>    name = request.get_json()["name"].strip()
    return {"tag": name}
