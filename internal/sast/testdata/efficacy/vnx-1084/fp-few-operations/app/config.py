import json
import os


def load_config(path):
    if not os.path.exists(path):
        return {}
    with open(path) as f:
        cfg = json.load(f)
    with open(path + ".local") as f:
        cfg.update(json.load(f))
    return cfg
