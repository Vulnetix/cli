import yaml
from yaml import CSafeLoader


def load_all(path, text):
    a = yaml.safe_load(text)
    b = yaml.load(text, Loader=yaml.SafeLoader)
    c = yaml.load(text, Loader=CSafeLoader)
    d = yaml.load(text, yaml.SafeLoader)
    e = yaml.load(
        text,
        Loader=yaml.SafeLoader,
    )
    f = yaml.load(text, Loader=yaml.BaseLoader)
    g = list(yaml.safe_load_all(text))
    h = yaml.full_load(text)
    i = yaml.load(text, Loader=yaml.FullLoader)
    return a, b, c, d, e, f, g, h, i
