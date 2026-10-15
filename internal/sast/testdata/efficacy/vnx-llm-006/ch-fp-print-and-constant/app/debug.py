def show(cursor, llm, question):
    sql = llm.invoke(question).content
    print(f"generated SQL: {sql}")
    cursor.execute("SELECT count(*) FROM audit")
    return sql
