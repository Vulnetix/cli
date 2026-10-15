from sqlalchemy import create_engine, text

engine = create_engine("postgresql://localhost/sales")


def ask(chain, question):
    sql = chain.invoke({"question": question})
    with engine.connect() as conn:
~>        rows = conn.execute(text(sql)).fetchall()
    return rows
