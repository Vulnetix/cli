import re

SCRIPT_RE = re.compile(r"<script.*?>", re.IGNORECASE)


def strip_scripts(comment):
    comment = re.sub(r"<script.*?>.*?</script>", "", comment, flags=re.I | re.S)
    return SCRIPT_RE.sub("", comment)
