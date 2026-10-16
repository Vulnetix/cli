import json


def apply_rule(path, ctx):
    with open(path) as fh:
        spec = json.load(fh)
    condition = spec["condition"]
~>    return eval(condition, {}, ctx)
