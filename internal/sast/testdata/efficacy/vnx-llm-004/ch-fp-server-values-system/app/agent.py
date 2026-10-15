import datetime

import anthropic

client = anthropic.Anthropic()
MODEL = "claude-sonnet-4-5"


def run(question, tools):
    tool_names = ", ".join(t.name for t in tools)
    return client.messages.create(
        model=MODEL,
        max_tokens=1024,
        system=f"Today is {datetime.date.today()}. You may call: {tool_names}.",
        messages=[{"role": "user", "content": question}],
    )
