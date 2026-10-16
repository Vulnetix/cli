import os

def pick_config(path):
    base, ext = os.path.splitext(path)
    if ext.lower() in (".yaml", ".yml"):
        return load_yaml(path)
    return load_json(path)
