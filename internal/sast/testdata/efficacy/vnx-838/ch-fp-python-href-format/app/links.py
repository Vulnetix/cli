import html
from urllib.parse import quote


def search_link(term):
    return '<a href="/search?q=%s">%s</a>' % (quote(term), html.escape(term))


def profile_link(user):
    return '<a href="/u/{}">profile</a>'.format(quote(user.slug))


def redirect_target(path):
    return "/login?next=" + quote(path)
