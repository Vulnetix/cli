import os
from anthropic import Anthropic

client = Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])
HF_TOKEN = os.getenv("HF_TOKEN")
if not key.startswith("sk-ant-"):
    raise ValueError("expected an sk-ant- key")
