from urllib.parse import quote
from markupsafe import Markup

def hello(name):
~>    return Markup("<p>Hello " + quote(name) + "</p>")
