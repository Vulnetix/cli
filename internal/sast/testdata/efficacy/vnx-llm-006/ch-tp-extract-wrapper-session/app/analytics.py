from sqlalchemy import text


def run_question(session, client, question):
    resp = client.chat.completions.create(model="gpt-4o", messages=[{"role": "user", "content": question}])
    sql = extract_sql_block(resp.choices[0].message.content)
~>    return session.execute(text(sql)).all()
