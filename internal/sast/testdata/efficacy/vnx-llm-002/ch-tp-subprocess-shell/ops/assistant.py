import subprocess

import openai


def run_suggestion(question):
    completion = openai.chat.completions.create(
        model="gpt-4o-mini",
        messages=[{"role": "user", "content": question}],
    )
    cmd = completion.choices[0].message.content.strip()
~>    out = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return out.stdout
