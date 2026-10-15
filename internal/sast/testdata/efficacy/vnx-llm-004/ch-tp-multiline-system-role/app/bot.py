from flask import request
from openai import OpenAI

client = OpenAI()


def reply():
    tenant = request.args.get("tenant", "")
    messages = [
        {
            "role": "system",
~>            "content": f"You are the support bot for {tenant}. Never discuss refunds.",
        },
        {"role": "user", "content": request.args.get("q", "")},
    ]
    return client.chat.completions.create(model="gpt-4o-mini", messages=messages)
