import lxml.etree
from flask import Flask, request
from lxml.etree import XMLParser, parse

app = Flask(__name__)


def make_parser():
~>    return XMLParser(resolve_entities=True)


@app.post("/upload")
def upload():
~>    tree = parse(request.files["doc"])
    return tree.getroot().tag


@app.post("/raw")
def raw():
~>    return lxml.etree.fromstring(request.data).tag
