import io

import joblib
import pandas as pd
import requests
import torch
from flask import request


def load_remote_weights(url):
    resp = requests.get(url, timeout=30)
    buf = io.BytesIO(resp.content)
    return torch.load(buf, weights_only=True)


def load_local_model():
    return joblib.load("/opt/models/estimator.joblib")


def upload_csv():
    upload = request.files["dataset"]
    frame = pd.read_csv(upload)
    return frame.to_json()
