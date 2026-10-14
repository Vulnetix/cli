import importlib


def load(name):
~>    from plugins.registry import REGISTRY
    module = importlib.import_module(name)
    REGISTRY[name] = module
    return module
