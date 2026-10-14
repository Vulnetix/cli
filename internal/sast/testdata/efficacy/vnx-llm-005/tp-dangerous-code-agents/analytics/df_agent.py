import pandas as pd
from langchain.chains import LLMMathChain
from langchain_experimental.agents import create_pandas_dataframe_agent
from langchain_experimental.pal_chain import PALChain
from langchain_experimental.tools.python.tool import PythonAstREPLTool


def build(llm, csv_path):
    df = pd.read_csv(csv_path)
    agent = create_pandas_dataframe_agent(
        llm,
        df,
~>        allow_dangerous_code=True,
    )
~>    repl = PythonAstREPLTool(locals={"df": df})
~>    math = LLMMathChain.from_llm(llm)
~>    pal = PALChain.from_math_prompt(llm, verbose=True)
    return agent, repl, math, pal
