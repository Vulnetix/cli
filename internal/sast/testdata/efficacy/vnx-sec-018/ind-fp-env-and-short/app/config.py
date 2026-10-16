import os
from openai import OpenAI

client = OpenAI(api_key=os.environ["OPENAI_API_KEY"])
hf_token = os.getenv("HF_TOKEN")

def looks_like_anthropic(k: str) -> bool:
    return k.startswith("sk-ant-")

def looks_like_hf(k):
    return k.startswith("hf_") and len(k) > 10

doc = "Keys begin with sk-proj- followed by random text"
