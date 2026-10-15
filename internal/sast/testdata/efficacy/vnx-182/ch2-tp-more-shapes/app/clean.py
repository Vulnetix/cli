import re


def clean_path(p):
~>    return re.sub(r"\.\./", "", p)


def clean_comment(text):
~>    return re.sub("<script>", "", text, flags=re.IGNORECASE)
