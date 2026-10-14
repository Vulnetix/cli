import logging

from jinja2 import Environment, select_autoescape

log = logging.getLogger(__name__)

# Never write env = Environment(autoescape=False) here.
env = Environment(autoescape=select_autoescape())


def check(environment):
    if environment.autoescape == False:
        log.warning("refusing an environment built with autoescape=False")
    return "set 'autoescape': False only for plain text"
