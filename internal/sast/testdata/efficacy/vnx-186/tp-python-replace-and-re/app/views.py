import re

from flask import request


def greet():
    name = request.args.get("name", "")
~>    name = name.replace("<script>", "").replace("</script>", "")
~>    comment = re.sub(r"<script.*?>.*?</script>", "", request.form["c"])
~>    if re.search(r"javascript:", request.form["url"]):
        return "blocked", 400
    return render(name, comment)


SQL_DENY = re.compile(
~>    r"\b(union|select|drop)\b"
)
