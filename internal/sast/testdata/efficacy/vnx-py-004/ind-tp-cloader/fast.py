import yaml


def parse(s):
~>    return yaml.load(s, Loader=yaml.CLoader)


def parse2(s):
~>    return yaml.load(s, yaml.CUnsafeLoader)
