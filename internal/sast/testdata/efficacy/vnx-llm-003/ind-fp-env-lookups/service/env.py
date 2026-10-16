import os
from openai import OpenAI

client = OpenAI(api_key=os.environ["OPENAI_API_KEY"])
backup = OpenAI(api_key=os.getenv("OPENAI_API_KEY_BACKUP"))
