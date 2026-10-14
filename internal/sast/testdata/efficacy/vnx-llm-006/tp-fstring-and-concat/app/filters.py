import anthropic
import psycopg2

client = anthropic.Anthropic()
db = psycopg2.connect("dbname=shop")


def search(question):
    msg = client.messages.create(
        model="claude-sonnet-4-5",
        max_tokens=256,
        messages=[{"role": "user", "content": f"Write a SQL WHERE clause for: {question}"}],
    )
    where_clause = msg.content[0].text
    cur = db.cursor()
~>    cur.execute(f"SELECT id, name FROM orders WHERE {where_clause}")
    rows = cur.fetchall()
    order_by = client.messages.create(model="claude-sonnet-4-5", max_tokens=64, messages=[{"role": "user", "content": question}]).content[0].text
~>    cur.execute("SELECT id FROM orders ORDER BY " + order_by)
    return rows
