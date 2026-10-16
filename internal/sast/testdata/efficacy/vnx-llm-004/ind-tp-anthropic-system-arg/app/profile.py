import anthropic
from flask import request

client = anthropic.Anthropic()


def answer():
    user_profile = request.json["profile"]
    return client.messages.create(
        model="claude-sonnet-4-5",
        max_tokens=400,
~>        system=f"Answer as a support agent. Customer profile: {user_profile}",
        messages=[{"role": "user", "content": "Hello"}],
    )
