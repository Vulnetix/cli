import pandas as pd
from langchain_community.utilities import SQLDatabase
from langchain_openai import ChatOpenAI
from sqlalchemy import create_engine, text

engine = create_engine("postgresql://localhost/warehouse")
db = SQLDatabase(engine)
llm = ChatOpenAI(model="gpt-4o")


def report(question):
    generated = llm.invoke(f"SQL for: {question}").content
    with engine.connect() as conn:
~>        rows = conn.execute(text(generated)).fetchall()
~>    frame = pd.read_sql(generated, engine)
    return rows, frame


def quick(question):
    query = llm.invoke(question).content
~>    return db.run(query)
