# yaml.load(stream) without a Loader is unsafe; we use safe_load below
import yaml

HINT = "replace yaml.load(data) with yaml.safe_load(data)"


def parse(data):
    return yaml.safe_load(data)
