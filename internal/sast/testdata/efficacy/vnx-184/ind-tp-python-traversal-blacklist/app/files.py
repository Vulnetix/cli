import os

~>PATH_BLACKLIST = ("../", "..\\", "/etc/passwd")


def open_user_file(name):
    if any(bad in name for bad in PATH_BLACKLIST):
        raise ValueError("invalid path")
    return open(os.path.join("/srv/userdata", name))
