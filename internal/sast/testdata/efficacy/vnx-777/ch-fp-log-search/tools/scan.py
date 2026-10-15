import re


def errors(lines):
    return [l for l in lines if re.search(r"ERROR\s+\d+", l)]


def has_digits(s):
    return bool(re.search(r"\d+", s))
