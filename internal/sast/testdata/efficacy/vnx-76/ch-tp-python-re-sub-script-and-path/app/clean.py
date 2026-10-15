import re


def clean_comment(comment):
~>    return re.sub(r"<script[^>]*>", "", comment, flags=re.IGNORECASE)


def clean_path(p):
~>    p = p.replace("../", "")
    return p
