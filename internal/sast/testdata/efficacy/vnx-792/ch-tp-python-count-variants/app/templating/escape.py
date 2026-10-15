import re


def escape_name(name):
~>    return name.replace('<', '&lt;', 1).replace('>', '&gt;', 1)


def strip_iframe(body):
~>    return re.sub(r"<iframe[^>]*>", "", body, count=1, flags=re.I)
