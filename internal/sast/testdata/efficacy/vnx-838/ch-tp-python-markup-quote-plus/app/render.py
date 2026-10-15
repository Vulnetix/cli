import urllib.parse

from markupsafe import Markup


def comment_html(comment):
~>    return Markup("<p class='c'>%s</p>" % urllib.parse.quote_plus(comment))
