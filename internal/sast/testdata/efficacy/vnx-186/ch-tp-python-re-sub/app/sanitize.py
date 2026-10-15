import re


def strip_scripts(comment):
~>    return re.sub(r"<script.*?>.*?</script>", "", comment)


def render(comment):
    return "<p>%s</p>" % strip_scripts(comment)
