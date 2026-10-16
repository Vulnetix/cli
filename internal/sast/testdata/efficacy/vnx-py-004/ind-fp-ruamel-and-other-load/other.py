import json
from ruamel.yaml import YAML

y = YAML(typ="safe")


def read(s, f, plugin):
    # yaml.load(s) with no loader is unsafe
    msg = "yaml.load(stream)"
    return y.load(s), json.load(f), plugin.load(s), msg
