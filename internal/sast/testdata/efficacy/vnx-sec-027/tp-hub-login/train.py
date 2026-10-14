from huggingface_hub import login
from transformers import AutoModel

~>login(token="hf_@@sample:[A-Za-z]{34}@@")
model = AutoModel.from_pretrained("acme/private-model")
