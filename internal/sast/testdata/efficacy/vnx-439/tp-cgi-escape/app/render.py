import cgi
from cgi import escape


def link(url, label):
~>    return '<a href="%s">%s</a>' % (cgi.escape(url), cgi.escape(label))


def title(t):
~>    return "<h1>" + escape(t) + "</h1>"
