from defusedxml.ElementTree import fromstring
from flask import request


def handle():
    data = request.get_data()
    root = fromstring(data)
    return root.tag
