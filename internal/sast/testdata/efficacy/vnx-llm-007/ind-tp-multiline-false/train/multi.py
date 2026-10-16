import torch

~>ckpt = torch.load(
    path,
    map_location="cpu",
    weights_only=False,
)
