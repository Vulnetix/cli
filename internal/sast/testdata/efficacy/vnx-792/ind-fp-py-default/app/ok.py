import html

def esc(s):
    s = s.replace("<", "&lt;")
    s = s.replace(">", "&gt;")
    return html.escape(s)
# s.replace("<", "&lt;", 1) in comment
