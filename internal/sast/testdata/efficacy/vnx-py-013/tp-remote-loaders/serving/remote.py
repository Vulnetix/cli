import io

import joblib
import pandas as pd
import requests
import torch
from flask import request


def load_remote_checkpoint(url):
    resp = requests.get(url, timeout=30)
    buf = io.BytesIO(resp.content)
~>    return torch.load(buf)


def upload_frame():
    upload = request.files["dataset"]
~>    return pd.read_pickle(upload)


def upload_estimator():
~>    return joblib.load(io.BytesIO(request.get_data()))


def safe_checkpoint(path):
    return torch.load(path, weights_only=True)
