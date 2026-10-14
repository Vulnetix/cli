import ast
import json

from openai import OpenAI

client = OpenAI()
HANDLERS = {"weather": lambda city: f"sunny in {city}"}


def answer(messages, tools):
    resp = client.chat.completions.create(model="gpt-4o", messages=messages, tools=tools)
    call = resp.choices[0].message.tool_calls[0]
    args = json.loads(call.function.arguments)
    return HANDLERS[call.function.name](**args)


def parse_list(messages):
    resp = client.chat.completions.create(model="gpt-4o", messages=messages)
    content = resp.choices[0].message.content
    return ast.literal_eval(content)


def run_fixed(cmd_name):
    exec(open("scripts/" + cmd_name + ".py").read())
