import json
import pickle

import joblib
import numpy as np
import pandas as pd
import torch
from safetensors.torch import load_file
from tensorflow import keras

a = np.load("emb.npy")
b = np.load("emb.npy", allow_pickle=False)
c = torch.load(path, weights_only=True)
d = load_file("model.safetensors")
e = json.load(fh)
pickle.dump(obj, fh)
blob = pickle.dumps(obj)
f = torch.jit.load("scripted.pt")
joblib.dump(model, "m.joblib")
df = pd.read_csv("x.csv")
m = keras.models.load_model("model.keras")
