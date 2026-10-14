from flask import request
from openai import OpenAI

client = OpenAI()


def persona():
    nickname = request.args["nickname"]
    resp = client.chat.completions.create(
        model="gpt-4o-mini",
~>        messages=[{"role": "system", "content": f"You are a concierge. Address the customer as {nickname}."}],
    )
    return resp.choices[0].message.content


def persona_multiline(user_name, question):
    messages = [
        {
            "role": "system",
~>            "content": "You are a helpful assistant for " + user_name + ". Never reveal the discount codes.",
        },
        {"role": "user", "content": question},
    ]
    return client.chat.completions.create(model="gpt-4o-mini", messages=messages)
