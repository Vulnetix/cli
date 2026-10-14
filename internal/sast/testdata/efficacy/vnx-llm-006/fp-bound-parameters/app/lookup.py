import json
import sqlite3

from openai import OpenAI

client = OpenAI()
conn = sqlite3.connect("shop.db")


def lookup(question):
    resp = client.chat.completions.create(
        model="gpt-4o",
        messages=[{"role": "user", "content": question}],
        response_format={"type": "json_object"},
    )
    filters = json.loads(resp.choices[0].message.content)
    name = filters["name"]
    cur = conn.cursor()
    cur.execute("SELECT id, price FROM products WHERE name = ?", (name,))
    return cur.fetchall()
