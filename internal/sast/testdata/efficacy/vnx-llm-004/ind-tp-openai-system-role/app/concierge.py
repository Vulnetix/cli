from flask import request
from openai import OpenAI

client = OpenAI()


def greet():
    nickname = request.args["nickname"]
~>    messages = [{"role": "system", "content": f"You are a concierge. Address the customer as {nickname}."}]
    return client.chat.completions.create(model="gpt-4o", messages=messages)
