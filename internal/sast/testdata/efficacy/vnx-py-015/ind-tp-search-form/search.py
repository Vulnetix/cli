import re
from flask import request


def find(text):
~>    return re.search(request.form["pattern"], text)
