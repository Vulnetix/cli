import os


def scripts(root):
    for name in os.listdir(root):
        if name.endswith(".py"):
            yield name


def content_type(path):
    if path.endswith(".html"):
        return "text/html; charset=utf-8"
    return "application/octet-stream"


def is_admin(user):
    return user.role == "admin"
