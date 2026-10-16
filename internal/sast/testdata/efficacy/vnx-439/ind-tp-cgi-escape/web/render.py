import cgi
from cgi import escape


def comment_html(author, body):
~>    safe_author = escape(author)
~>    safe_body = cgi.escape(body, quote=True)
    return "<p><b>%s</b>: %s</p>" % (safe_author, safe_body)
