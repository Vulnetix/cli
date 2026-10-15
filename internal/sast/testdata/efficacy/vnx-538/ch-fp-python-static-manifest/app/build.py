import json
import os

STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")


def write_manifest(manifest):
    open(os.path.join(STATIC_DIR, "manifest.json"), "w").write(json.dumps(manifest))
    with open(os.path.join(STATIC_DIR, "version.txt"), "w") as fh:
        fh.write(manifest["version"])
