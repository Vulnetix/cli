import os


def safe_name(name):
    while "../" in name:
        name = name.replace("../", "")
    return name


def safe_name_two(name):
    prev = None
    while prev != name:
        prev = name
        name = name.replace("..", "")
    return name


def resolved(base, name):
    full = os.path.realpath(os.path.join(base, name))
    if not full.startswith(base + os.sep):
        raise ValueError("outside base")
    return full
