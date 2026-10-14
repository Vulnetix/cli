import pandas as pd
from langchain_experimental.agents import create_pandas_dataframe_agent


def build(llm, csv_path):
    df = pd.read_csv(csv_path)
    return create_pandas_dataframe_agent(
        llm,
        df,
        allow_dangerous_code=False,
    )
