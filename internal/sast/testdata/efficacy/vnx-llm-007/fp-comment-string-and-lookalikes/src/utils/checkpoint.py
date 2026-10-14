import json
import torch

# Never call torch.load(path) on untrusted files; we use weights_only below.
HELP = "Checkpoints are read with torch.load(path, weights_only=True)."


def read_meta(path):
    with open(path) as fh:
        return json.load(fh)


def safe(path):
    """torch.load(path) is unsafe; this wrapper is not."""
    return torch.load(path, weights_only=True)


def my_torch_loader(path):
    return mytorch.load(path)
