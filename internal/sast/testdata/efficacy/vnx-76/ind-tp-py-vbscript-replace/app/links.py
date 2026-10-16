import re


def clean_href(href):
~>    href = href.replace("vbscript:", "")
    return href


def strip_frames(markup):
~>    return re.sub(r"<frameset", "", markup)
