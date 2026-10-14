import os
from huggingface_hub import login

token = os.environ["HF_TOKEN"]
login(token=token)
HF_TOKEN_PATTERN = r"hf_[A-Za-z]{34}"
