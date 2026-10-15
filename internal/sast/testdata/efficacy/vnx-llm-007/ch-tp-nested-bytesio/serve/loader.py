import io

import torch


def from_blob(model, blob: bytes):
~>    model.load_state_dict(torch.load(io.BytesIO(blob)))
    return model.eval()
