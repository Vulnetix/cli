import sqlite3

import anthropic

client = anthropic.Anthropic()


def apply_suggested_migration(schema: str):
    message = client.messages.create(model="claude-sonnet-4-5", max_tokens=2048, messages=[{"role": "user", "content": schema}])
    script = message.content[0].text.strip().removeprefix("```sql").removesuffix("```")
    con = sqlite3.connect("app.db")
~>    con.executescript(script)
