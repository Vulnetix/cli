def clean(name):
    while "../" in name:
        name = name.replace("../", "")
    return name
