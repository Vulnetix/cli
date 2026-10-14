import os


def read_shadow_entry(user):
~>    os.seteuid(0)
    with open("/etc/shadow") as shadow:
        for line in shadow:
            if line.startswith(user + ":"):
                return line
    return None
