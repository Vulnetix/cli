def basename(path):
    return path[path.rfind("/") + 1:]


def ext(name):
    i = name.rfind(".")
    return name[i:] if i >= 0 else ""
