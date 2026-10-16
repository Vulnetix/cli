import torch
from tensorflow import keras


def a(path):
~>    return torch.load(path, weights_only=False)


def b(path):
~>    return keras.models.load_model(path, safe_mode=False)
