import pandas as pd
from sqlalchemy import text


def run(llm, question, conn, engine):
    generated = llm.invoke(f"SQL for: {question}").content
~>    rows = conn.execute(text(generated)).fetchall()
~>    frame = pd.read_sql(generated, engine)
    return rows, frame
