from langchain_community.tools import DuckDuckGoSearchRun, ShellTool
from langgraph.prebuilt import create_react_agent


def ops_agent(model):
~>    tools = [DuckDuckGoSearchRun(), ShellTool(ask_human_input=False)]
    return create_react_agent(model, tools=tools)
