import torch
from torch import nn


class Classifier(nn.Module):
    def __init__(self):
        super().__init__()
        self.fc = nn.Linear(128, 10)


def load_model(path):
~>    model = torch.load(path)
    model.eval()
    return model


def load_uploaded(upload_dir, name):
    checkpoint_path = f"{upload_dir}/{name}.pt"
~>    state = torch.load( checkpoint_path, map_location="cpu")
    net = Classifier()
    net.load_state_dict(state)
    return net
