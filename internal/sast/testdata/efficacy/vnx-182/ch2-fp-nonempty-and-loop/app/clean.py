import re


def mask(p):
    return p.replace("../", "_")


def strip_all(p):
    while "../" in p:
        p = p.replace("../", "")
    return p


def tidy(text):
    return text.replace("  ", " ").replace("\t", "")
