from flask import request
from openai import OpenAI

client = OpenAI()


def chat():
    text = request.json["text"]
    return client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[
            {"role": "system", "content": "You are a terse assistant."},
            {"role": "user", "content": text},
        ],
    )
