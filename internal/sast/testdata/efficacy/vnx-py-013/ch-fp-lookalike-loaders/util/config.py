import json

import yaml


def safe_pickle_loads(data):
    raise NotImplementedError("pickle is not accepted from clients")


def read(path):
    with open(path) as fh:
        return json.loads(fh.read())


def read_yaml(path):
    with open(path) as fh:
        return yaml.safe_load(fh)


HELP = "Never call pickle.loads() on data from the network."
