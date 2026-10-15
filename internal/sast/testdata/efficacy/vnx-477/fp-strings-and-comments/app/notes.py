# import imp  -- removed in 3.12, use importlib
# ssl.wrap_socket(sock) is gone; use SSLContext.wrap_socket
MIGRATION = "replace cgi.escape( with html.escape("
HINT = 'from distutils.core import setup'


def note():
    """Do not call time.clock() or base64.encodestring()."""
    return MIGRATION, HINT
