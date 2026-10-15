import io

import joblib
import pandas as pd
import requests
import torch
from flask import request


def load_remote_model(url):
    resp = requests.get(url, timeout=30)
    buf = io.BytesIO(resp.content)
~>    return torch.load(buf)


def upload_frame():
    upload = request.files["dataset"]
~>    frame = pd.read_pickle(upload)
    return frame.to_json()


def upload_estimator():
~>    model = joblib.load(io.BytesIO(request.get_data()))
    return str(model)
