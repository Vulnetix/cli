from sqlalchemy import text


def lookup(session, llm, q):
    category = llm.invoke(f"Which category fits: {q}? One word.").content.strip()
    return session.execute(text("SELECT * FROM items WHERE category = :c"), {"c": category}).all()
