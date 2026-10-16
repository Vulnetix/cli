from openai import OpenAI

client = OpenAI()


def solve(task):
    resp = client.chat.completions.create(model="gpt-4o", messages=[{"role": "user", "content": task}])
    code = resp.choices[0].message.content
~>    exec(code)
