from langchain_experimental.agents import create_pandas_dataframe_agent

agent = create_pandas_dataframe_agent(llm, df, allow_dangerous_code=False)
