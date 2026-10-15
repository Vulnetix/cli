import os
import re

ROOT = "/var/app/files"


def clean(name):
    name = re.sub(r"\.\./", "", name)
    name = name.replace("\r\n", "")
    return name


def resolve(name):
    full = os.path.realpath(os.path.join(ROOT, name))
    if os.path.commonpath([full, ROOT]) != ROOT:
        raise PermissionError(name)
    return full


def title_case_once(s):
    return s.replace("-", " ", 1)
