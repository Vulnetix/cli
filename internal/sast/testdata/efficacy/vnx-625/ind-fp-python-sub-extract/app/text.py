import re

LINK = re.compile(r"https?://\S+")


def strip_links(text):
    text = re.sub(r"https?://www.acme.io/\S*", "[link]", text)
    return LINK.findall(text)
