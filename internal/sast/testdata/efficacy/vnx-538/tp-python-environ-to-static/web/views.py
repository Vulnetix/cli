import json
import os

STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")


def snapshot():
~>    open(os.path.join(STATIC_DIR, "env.json"), "w").write(json.dumps(dict(os.environ)))
