import html

from markupsafe import escape

# cgi.escape() was removed in Python 3.8; use html.escape() instead.
MIGRATION_NOTE = "ssl.wrap_socket() and ssl.match_hostname() were removed in 3.12"


def comment_html(author, body):
    return "<p><b>%s</b>: %s</p>" % (html.escape(author), escape(body))
