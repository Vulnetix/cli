import ast
from openai import OpenAI

client = OpenAI()


def parse_list(text):
    resp = client.chat.completions.create(model="gpt-4o", messages=[{"role": "user", "content": text}])
    data = resp.choices[0].message.content
    return ast.literal_eval(data)
