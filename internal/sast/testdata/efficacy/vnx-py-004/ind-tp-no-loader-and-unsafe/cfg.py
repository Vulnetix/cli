import yaml
import yaml as y
from yaml import load


def read(stream, body, f):
~>    data = yaml.load(stream)
~>    job = yaml.load(body, Loader=yaml.Loader)
~>    other = y.load(f, y.UnsafeLoader)
~>    third = load(stream)
~>    docs = list(yaml.load_all(stream))
~>    x = yaml.unsafe_load(body)
    return data, job, other, third, docs, x
