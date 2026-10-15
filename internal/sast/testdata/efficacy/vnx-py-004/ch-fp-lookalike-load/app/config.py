import json

import yaml


def go(config, fh, obj):
    settings = config.load("settings.yaml")
    payload = json.load(fh)
    text = yaml.dump(obj)
    # yaml.load(fh) without a Loader is unsafe; we never do that.
    return settings, payload, text
