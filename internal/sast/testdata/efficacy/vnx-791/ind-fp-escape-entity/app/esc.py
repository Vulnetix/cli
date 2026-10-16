import html

def esc(s):
    s = s.replace("<", "&lt;").replace(">", "&gt;")
    return html.escape(s)
