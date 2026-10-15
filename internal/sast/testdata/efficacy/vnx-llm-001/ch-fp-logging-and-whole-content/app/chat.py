import logging
from flask import request
from openai import OpenAI

log = logging.getLogger(__name__)
client = OpenAI()


def chat():
    user_input = request.json["message"]
    log.info(f"user asked: {user_input}")
    resp = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[
            {"role": "system", "content": "You are a helpful assistant."},
            {"role": "user", "content": user_input},
        ],
    )
    return resp.choices[0].message.content
