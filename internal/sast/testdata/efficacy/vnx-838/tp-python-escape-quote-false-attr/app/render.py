import cgi
import html


def field(name, value):
~>    return f'<input name="{name}" value="{html.escape(value, quote=False)}">'


def link_title(t):
~>    return '<a title="' + cgi.escape(t) + '">more</a>'
