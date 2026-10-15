import json
import subprocess

from openai import OpenAI

client = OpenAI()
HANDLERS = {"weather": get_weather, "time": get_time}


def step(messages):
    resp = client.chat.completions.create(model="gpt-4o-mini", messages=messages, tools=TOOLS)
    call = resp.choices[0].message.tool_calls[0]
    args = json.loads(call.function.arguments)
    result = HANDLERS[call.function.name](**args)
    subprocess.run(["logger", "tool call finished"], check=False)
    return result
