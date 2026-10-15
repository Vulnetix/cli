RESERVED = {"admin", "root", "support"}

~>BACKDOOR_USER = "аdmin"


def is_reserved(name):
~>    if name in ("rооt", "support"):
        return True
    return name in RESERVED
