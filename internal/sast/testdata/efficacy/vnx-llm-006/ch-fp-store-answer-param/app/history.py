def save(db, client, question):
    resp = client.chat.completions.create(model="gpt-4o-mini", messages=[{"role": "user", "content": question}])
    answer = resp.choices[0].message.content
    db.execute("INSERT INTO chat_log (question, answer) VALUES (?, ?)", (question, answer))
    db.execute(
        "UPDATE stats SET answered = answered + 1 WHERE day = %s",
        (today(),),
    )
    db.commit()
