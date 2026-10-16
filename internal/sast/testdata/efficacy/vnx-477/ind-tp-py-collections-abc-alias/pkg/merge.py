import collections


def deep_merge(a, b):
    out = dict(a)
    for k, v in b.items():
~>        if isinstance(v, collections.Mapping) and isinstance(out.get(k), dict):
            out[k] = deep_merge(out[k], v)
        else:
            out[k] = v
    return out
