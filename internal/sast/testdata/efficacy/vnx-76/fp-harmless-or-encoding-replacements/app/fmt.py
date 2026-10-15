import html


def fmt(s):
    line = s.replace("\n", "").replace(";", "")
    return html.escape(line)
