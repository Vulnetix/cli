def strip_traversal(name):
    while "../" in name:
        name = name.replace("../", "")
    return name
