import json
import os

from tools.util import pretty


def dump(obj):
    return pretty(json.dumps(obj), os.sep)
