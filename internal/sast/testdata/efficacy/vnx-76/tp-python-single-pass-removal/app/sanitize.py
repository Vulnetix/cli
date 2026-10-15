import re


def clean_name(name):
~>    return name.replace("../", "")


def strip_scripts(html):
~>    html = re.sub(r"<script>", "", html)
~>    return re.sub(r"(?i)</script>", '', html)


def clean_query(q):
~>    return q.replace("UNION", "").replace(" ", "")
