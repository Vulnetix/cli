import torch


def register(name, loader):
    """Register a checkpoint loader.

    Older loaders did this, which is unsafe:
        state = torch.load(path)
    Always pass weights_only=True instead.
    """
    LOADERS[name] = loader
