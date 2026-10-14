from flask import request
from openai import OpenAI

client = OpenAI()


def persona():
    nickname = request.args["nickname"]
    resp = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[{"role": "system", "content": f"Address the customer as {nickname}."}],
    )
    return resp.choices[0].message.content
