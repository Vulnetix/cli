import json
import os
import sys

import yaml


def load(config_path):
    ext = os.path.splitext(config_path)[1].lower()
    if ext in (".yml", ".yaml"):
        with open(config_path) as fh:
            return yaml.safe_load(fh)
    if ext == ".json":
        with open(config_path) as fh:
            return json.load(fh)
    raise SystemExit(f"unsupported config format: {ext}")


if __name__ == "__main__":
    print(load(sys.argv[1]))
