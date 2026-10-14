from plugins.hooks import run_hooks

REGISTRY = {}


def register(name, module):
    REGISTRY[name] = module
    run_hooks(name)
