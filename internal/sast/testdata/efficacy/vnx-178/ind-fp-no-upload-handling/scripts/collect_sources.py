import os


def python_sources(root):
    found = []
    for dirpath, _dirs, files in os.walk(root):
        for filename in files:
            if filename.endswith(".py") or filename.endswith(".sh"):
                found.append(os.path.join(dirpath, filename))
    return found
