import numpy as np
import torch
from tensorflow import keras

~>emb = np.load("emb.npy", allow_pickle=True)
~>state = torch.load(ckpt_path, map_location="cpu")
~>legacy = torch.load(old_path, weights_only=False)
~>clf = keras.models.load_model("model.keras", safe_mode=False)
~>table = np.load(
    table_path,
    allow_pickle=True,
)
