import html
from urllib.parse import quote

def a(text):
    return "<p>" + html.escape(text, quote=False) + "</p>"

def b(value):
    return f'<input value="{html.escape(value)}">'

def c(path):
    return '<a href="/files/' + quote(path) + '">download</a>'

def d(q):
    return "/search?q=" + quote(q)
