import re

import anthropic

client = anthropic.Anthropic()


def extract(text):
    m = re.search(r"```python\n(.*?)```", text, re.S)
    return m.group(1) if m else text


def auto_fix(trace):
    message = client.messages.create(
        model="claude-sonnet-4-5",
        max_tokens=1024,
        messages=[{"role": "user", "content": trace}],
    )
    raw = message.content[0].text
    patch_code = extract(raw)
~>    exec(compile(patch_code, "<llm>", "exec"))
