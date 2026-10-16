from langchain.agents import load_tools

~>tools = load_tools(["terminal", "llm-math"], llm=llm)
