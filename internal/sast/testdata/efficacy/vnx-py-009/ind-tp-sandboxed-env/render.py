from jinja2 import BaseLoader
from jinja2.sandbox import SandboxedEnvironment


def build_env():
~>    env = SandboxedEnvironment(loader=BaseLoader(), autoescape=False)
    env.globals["site"] = "example"
    return env
