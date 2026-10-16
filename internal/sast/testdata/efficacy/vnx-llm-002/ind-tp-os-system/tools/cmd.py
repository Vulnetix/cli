import os
import anthropic

client = anthropic.Anthropic()


def go(task):
    msg = client.messages.create(model="claude-sonnet-4-5", max_tokens=200,
                                 messages=[{"role": "user", "content": task}])
    cmd = msg.content[0].text
~>    os.system(cmd)
