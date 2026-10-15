import html


def search_box(q):
~>    return '<input name="q" value="%s">' % html.escape(q, quote=False)


def tip(text):
~>    return '<abbr title="{}">?</abbr>'.format(html.escape(text, quote=False))
