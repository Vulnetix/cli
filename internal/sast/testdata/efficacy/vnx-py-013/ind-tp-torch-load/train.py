import torch


def load_model(model_path):
~>    model = torch.load(model_path, map_location="cpu")
    model.eval()
    return model
