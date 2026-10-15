from langchain.agents import AgentExecutor, create_react_agent
from langchain_experimental.tools import PythonREPLTool as CodeRunner


def make_agent(llm, prompt):
~>    tools = [CodeRunner()]
    agent = create_react_agent(llm, tools, prompt)
    return AgentExecutor(agent=agent, tools=tools)
