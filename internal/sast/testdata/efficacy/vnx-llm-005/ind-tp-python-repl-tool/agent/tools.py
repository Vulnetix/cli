from langchain.agents import initialize_agent
from langchain_experimental.tools import PythonREPLTool

~>tools = [PythonREPLTool()]
agent = initialize_agent(tools, llm, agent="zero-shot-react-description")
