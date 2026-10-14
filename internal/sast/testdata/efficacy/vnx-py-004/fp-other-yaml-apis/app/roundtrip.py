import json

from ruamel.yaml import YAML


class Store:
    def __init__(self):
        self.yaml = YAML(typ="safe")

    def read(self, fh):
        doc = self.yaml.load(fh)
        cfg = YAML().load(fh)
        raw = json.load(fh)
        return doc, cfg, raw
