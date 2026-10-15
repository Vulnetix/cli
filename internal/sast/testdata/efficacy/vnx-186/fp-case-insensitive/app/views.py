import html
import re

SCRIPT_RE = re.compile(r"<script.*?>.*?</script>", re.IGNORECASE | re.DOTALL)


def clean(value):
    value = SCRIPT_RE.sub("", value)
    value = re.sub(r"javascript:", "", value, flags=re.I)
    if re.search(r"(?i)\bunion\b", value):
        raise ValueError("blocked")
    return html.escape(value)
