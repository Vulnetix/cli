import pandas as pd


def report(llm, engine, question):
    answer = llm.invoke(f"Write one SQL query for: {question}").content
~>    return pd.read_sql_query(answer, engine)
