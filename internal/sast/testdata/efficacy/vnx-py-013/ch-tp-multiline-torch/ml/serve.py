import io

import pandas as pd
import torch


def load_model(path):
~>    model = torch.load(
        path,
        map_location="cpu",
    )
    model.eval()
    return model


def load_frame(blob):
~>    return pd.read_pickle(io.BytesIO(blob))
