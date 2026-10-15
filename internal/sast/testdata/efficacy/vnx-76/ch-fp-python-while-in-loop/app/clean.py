import html


def clean_path(p):
    while "../" in p:
        p = p.replace("../", "")
    return p


def show(text):
    text = text.replace("\r\n", "")
    return html.escape(text).replace("<", "&lt;")
