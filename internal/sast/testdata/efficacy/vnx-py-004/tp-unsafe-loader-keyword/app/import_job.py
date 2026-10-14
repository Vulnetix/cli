import yaml
from flask import request


def import_job():
    body = request.get_data()
~>    job = yaml.load(body, Loader=yaml.Loader)
~>    alt = yaml.load(body, Loader = yaml.UnsafeLoader)
~>    fast = yaml.load(body, Loader=yaml.CLoader)
    return job, alt, fast
