def explain():
    # fh = open(path) leaks the handle when nobody closes it
    return "fh = open(path)"
