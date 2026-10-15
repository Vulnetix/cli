import re


def strip_scripts(body):
~>    return re.sub(r"<script[^>]*>.*?</script>", "", body, flags=re.I | re.S)
