import re

SCRIPT_RE = re.compile(r"<script[^>]*>.*?</script>", re.I | re.S)
HANDLER_RE = re.compile(r"\son\w+\s*=\s*\"[^\"]*\"", re.I)


def clean_comment(body):
~>    body = SCRIPT_RE.sub("", body)
~>    body = HANDLER_RE.sub('', body)
    return body


def clean_attrs(html):
~>    return re.sub(r"\son\w+\s*=", "", html)
