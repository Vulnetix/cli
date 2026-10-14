import json as _json


def dumps(obj):
    return _json.dumps(obj, sort_keys=True)
