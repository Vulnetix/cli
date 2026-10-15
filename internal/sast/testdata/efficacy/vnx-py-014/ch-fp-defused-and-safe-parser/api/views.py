import defusedxml.lxml
from flask import Flask, request
from lxml import etree

app = Flask(__name__)

SAFE = etree.XMLParser(resolve_entities=False, no_network=True, load_dtd=False)


@app.post("/a")
def a():
    root = defusedxml.lxml.fromstring(request.data)
    return root.tag


@app.post("/b")
def b():
    root = etree.fromstring(request.data, parser=SAFE)
    return root.tag
