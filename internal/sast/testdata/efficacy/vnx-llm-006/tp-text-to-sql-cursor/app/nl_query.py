import sqlite3

from openai import OpenAI

client = OpenAI()
conn = sqlite3.connect("shop.db")


def ask(question):
    resp = client.chat.completions.create(
        model="gpt-4o",
        messages=[
            {"role": "system", "content": "Translate the question to SQLite SQL. Reply with SQL only."},
            {"role": "user", "content": question},
        ],
    )
    sql = resp.choices[0].message.content.strip()
    cursor = conn.cursor()
~>    cursor.execute(sql)
    return cursor.fetchall()


def ask_script(question):
    r = client.chat.completions.create(model="gpt-4o", messages=[{"role": "user", "content": question}])
~>    conn.executescript(r.choices[0].message.content)
