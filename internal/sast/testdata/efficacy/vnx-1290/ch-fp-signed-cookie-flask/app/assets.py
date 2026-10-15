import base64
from flask import request


def theme_css():
    # decode the theme blob the browser keeps
    blob = request.cookies.get("theme")
    css = base64.b64decode(blob).decode() if blob else ""
    return css
