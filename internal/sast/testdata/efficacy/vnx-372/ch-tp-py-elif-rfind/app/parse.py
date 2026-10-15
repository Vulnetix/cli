def split_ext(name):
    if name.endswith("/"):
        return name, ""
~>    elif name.rfind("."):
        dot = name.rfind(".")
        return name[:dot], name[dot:]
    return name, ""
