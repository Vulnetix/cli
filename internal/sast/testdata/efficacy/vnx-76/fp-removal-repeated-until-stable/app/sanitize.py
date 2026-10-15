def clean_name(name):
    while "../" in name:
        name = name.replace("../", "")
    return name
