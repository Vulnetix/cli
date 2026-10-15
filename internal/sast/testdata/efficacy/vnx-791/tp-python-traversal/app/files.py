import os
import re

BASE = "/srv/files"


def open_user_file(name):
~>    name = name.replace('../', '')
    return open(os.path.join(BASE, name))


def open_other(name):
~>    safe = re.sub(r'\.\./', '', name)
    return open(os.path.join(BASE, safe))
