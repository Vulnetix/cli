import html


def first_word(s):
    return s.replace(" ", "_", 1)


def unescape_once(s):
    return html.unescape(s)


def strip_prefix(s):
    return s.replace("v", "", 1)


def escape_all(s):
    return s.replace("<", "&lt;").replace(">", "&gt;")
