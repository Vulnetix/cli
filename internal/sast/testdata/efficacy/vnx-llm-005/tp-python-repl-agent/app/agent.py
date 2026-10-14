from langchain.agents import AgentType, initialize_agent
from langchain_experimental.agents.agent_toolkits import create_python_agent
from langchain_experimental.tools import PythonREPLTool
from langchain_experimental.utilities import PythonREPL
from langchain_core.tools import Tool
from langchain_openai import ChatOpenAI

llm = ChatOpenAI(model="gpt-4o-mini", temperature=0)

~>tools = [PythonREPLTool()]
agent = initialize_agent(tools, llm, agent=AgentType.ZERO_SHOT_REACT_DESCRIPTION)

~>coder = create_python_agent(llm=llm, tool=PythonREPLTool(), verbose=True)

~>python_repl = PythonREPL()
repl_tool = Tool(
    name="python_repl",
    description="Runs python code.",
    func=python_repl.run,
)
