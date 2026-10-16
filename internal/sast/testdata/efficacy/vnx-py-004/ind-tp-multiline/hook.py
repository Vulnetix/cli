import yaml
from flask import request


def webhook():
~>    payload = yaml.load(
        request.data,
        Loader=yaml.UnsafeLoader,
    )
    return payload


def cfg(path):
    with open(path) as fh:
~>        return yaml.load(
            fh,
        )
