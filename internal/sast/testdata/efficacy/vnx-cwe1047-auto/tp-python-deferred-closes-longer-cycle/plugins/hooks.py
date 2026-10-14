from plugins import loader

HOOKS = []


def run_hooks(name):
    for hook in HOOKS:
        hook(loader.load(name))
