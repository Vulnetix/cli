import re


def safe(name):
~>    return name.replace("../", "", 1)


def safe2(cmd):
~>    return re.sub(r";", "", cmd, count=1)
