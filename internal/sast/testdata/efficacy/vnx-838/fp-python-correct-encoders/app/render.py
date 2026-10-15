import html
from urllib.parse import quote


def field(name, value):
    return f'<input name="{name}" value="{html.escape(value)}">'


def body(text):
    return "<p>" + html.escape(text, quote=False) + "</p>"


def link(q):
    return f'<a href="/search?q={quote(q)}">again</a>'


def redirect_url(q):
    return "/search?q=" + quote(q)
