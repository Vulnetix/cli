# if f.filename.endswith(".php"): reject -- misses "shell.PHP"
HELP = 'f.filename.endswith(".php") is case-sensitive'


def describe():
    return HELP
