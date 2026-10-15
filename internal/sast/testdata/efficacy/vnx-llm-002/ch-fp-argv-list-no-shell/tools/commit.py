import subprocess


def commit_with_ai_message(client, diff):
    resp = client.chat.completions.create(model="gpt-4o-mini", messages=[{"role": "user", "content": diff}])
    message = resp.choices[0].message.content
    subprocess.run(["git", "commit", "-m", message], check=True)
