import yaml
from yaml import SafeLoader


def a(s):
    return yaml.safe_load(s)


def b(s):
    return yaml.load(s, Loader=yaml.SafeLoader)


def c(s):
    return yaml.load(s, Loader=yaml.CSafeLoader)


def d(s):
    return yaml.load(s, SafeLoader)


def e(s):
    return yaml.load(s, Loader=yaml.BaseLoader)


def f(s):
    return yaml.load(
        s,
        Loader=yaml.SafeLoader,
    )


def g(s):
    return yaml.full_load(s)


def h(s):
    return yaml.load(s, Loader=yaml.FullLoader)
