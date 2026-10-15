import pandas as pd
from langchain_experimental.agents import create_pandas_dataframe_agent


def analyst(llm, path):
    df = pd.read_csv(path)
    return create_pandas_dataframe_agent(
        llm,
        df,
        verbose=True,
~>        allow_dangerous_code=True,
    )
