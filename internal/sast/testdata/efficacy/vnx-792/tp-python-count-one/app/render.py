import re


def escape(s):
~>    return s.replace("<", "&lt;", 1)


def strip_script(s):
~>    return re.sub(r"<script>", "", s, count=1)


def strip_script2(s):
~>    return re.sub(r"<script>", "", s, 1)
