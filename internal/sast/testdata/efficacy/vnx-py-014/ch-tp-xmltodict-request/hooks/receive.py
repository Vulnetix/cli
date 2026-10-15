import xmltodict
from flask import Flask, request

app = Flask(__name__)


@app.post("/hook")
def hook():
~>    doc = xmltodict.parse(request.get_data(), disable_entities=False)
    return {"keys": list(doc)}
