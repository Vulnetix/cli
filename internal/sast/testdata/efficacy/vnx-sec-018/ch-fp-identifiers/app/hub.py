import os
from huggingface_hub import hf_hub_download

HF_HUB_ENABLE_HF_TRANSFER = os.environ.get("HF_HUB_ENABLE_HF_TRANSFER", "0")
hf_modelrepositoryidentifierfordownloadcache = "bert-base-uncased"
path = hf_hub_download(repo_id="bert-base-uncased", filename="config.json")
token = os.environ["HF_TOKEN"]
