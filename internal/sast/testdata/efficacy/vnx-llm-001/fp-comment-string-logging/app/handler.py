import logging

from flask import request
from openai import OpenAI

client = OpenAI()
log = logging.getLogger(__name__)

# Bad: content=f"Answer: {user_input}" mixes instructions with user data.
DOC = 'content=f"Answer: {user_input}" is prompt injection'


def handle():
    user_input = request.form["q"]
    log.info(f"received question from user: {user_input}")
    resp = client.chat.completions.create(model="gpt-4o-mini", messages=[{"role": "user", "content": user_input}])
    log.debug("answered " + user_input)
    return resp.choices[0].message.content
