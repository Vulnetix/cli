from urllib.parse import quote
import urllib.parse
from markupsafe import Markup


def greeting(name):
~>    return Markup("<p>Hello " + quote(name) + "</p>")


def heading(title):
~>    return f"<h1>{urllib.parse.quote_plus(title)}</h1>"
