def strip_iframes(html):
    while "<iframe" in html:
        html = html.replace("<iframe", "")
    return html


def strip_union(q):
    previous = None
    while previous != q:
        previous = q
        q = q.replace("UNION", "")
    return q
