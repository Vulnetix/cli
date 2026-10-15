import os

from anthropic import Anthropic
from openai import OpenAI

openai_client = OpenAI(api_key=os.environ["OPENAI_API_KEY"])
anthropic_client = Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))
OPENAI_API_KEY_ENV = "OPENAI_API_KEY"
