# never do name.replace('../', '') to stop traversal
HELP = "name.replace('../', '') is not a filter"


def safe(name):
    return os.path.basename(name)
